package events

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"

	"github.com/umputun/tg-spam/app/bot"
)

// captchaPrefix marks callback data of captcha buttons, "C<userID>:<choice>" with choice a candidate number
const captchaPrefix = "C"

const (
	captchaCodeLen = 2
	captchaChoices = 6 // candidate numbers offered, the code among them: a guess passes 1 in 6
	captchaWorkers = 4 // concurrent verifications, each makes a few API calls and an upload

	// a failed captcha bans for captchaCooldown, doubled on every further failure up to captchaMaxCooldown.
	// failures older than captchaMaxCooldown are forgotten
	captchaCooldown    = 5 * time.Minute
	captchaMaxCooldown = 24 * time.Hour
)

// captchaGrace extends the join restriction past the captcha deadline. the restriction expires on its own,
// so a member whose captcha was lost (bot restart, failed cleanup) is not muted forever. it also keeps
// until_date beyond the 30 seconds telegram treats as "forever"
const captchaGrace = time.Minute

// captcha verifies new members of the primary chat. a member is muted on join and gets an animation that
// shows a number only in motion (see renderMotionCaptcha) with candidate numbers under it. choosing the
// right one lifts the mute. a wrong number, the timeout or leaving with the captcha unsolved is a failure:
// the member is banned for a cooldown that doubles with each failure, so guessing by rejoining stays slow.
// safe for concurrent use: callbacks come from the update loop, timeouts from timer goroutines and the
// verification itself from worker goroutines.
type captcha struct {
	tbAPI   TbAPI
	chatID  int64
	timeout time.Duration
	message string // prompt template with {user} and {timeout}, empty for the mode default
	// timeoutMute mutes a member who times out for good instead of banning for the cooldown; the member stays in
	// the chat until an admin lifts the restriction. the permanent mute is not recorded in muted, so on a rejoin
	// it reads as anybody's restriction and is kept, with no new captcha that could lift it
	timeoutMute bool
	render      func(code string) ([]byte, error) // draws the challenge image
	turnstile   *turnstile                        // set in Turnstile mode, nil for the motion animation

	workers chan struct{}  // limits concurrent verifications
	running sync.WaitGroup // verifications in progress, waited for by Stop

	mu       sync.Mutex
	pending  map[int64]*pendingCaptcha  // by user ID
	tests    map[int64]*pendingCaptcha  // test challenges in private chats, by user ID
	nonces   map[string]*pendingCaptcha // posted Turnstile challenges, by page nonce
	failures map[int64]captchaFailure   // by user ID
	muted    map[int64]time.Time        // members under the captcha's own mute, by user ID, to its expiry
}

type pendingCaptcha struct {
	user   bot.User
	chatID int64  // chat the challenge is posted in
	msgID  int    // captcha message, 0 until posted
	code   string // the number to choose, or the page nonce in Turnstile mode; set when posted
	chosen string // candidate the member pressed
	page   bool   // posted as a turnstile page rather than the animation
	lang   string // member's telegram language, for the texts the bot shows them
	timer  *time.Timer
}

type captchaFailure struct {
	count   int
	last    time.Time
	forever bool // the last failure muted the member for good (timeout in the mute mode)
}

func newCaptcha(tbAPI TbAPI, chatID int64, timeout time.Duration, message string) *captcha {
	return &captcha{tbAPI: tbAPI, chatID: chatID, timeout: timeout, message: message, render: renderMotionCaptcha,
		workers: make(chan struct{}, captchaWorkers), pending: make(map[int64]*pendingCaptcha),
		tests: make(map[int64]*pendingCaptcha), nonces: make(map[string]*pendingCaptcha),
		failures: make(map[int64]captchaFailure),
		muted:    make(map[int64]time.Time)}
}

// Start verifies a member who has just joined. it only marks the member pending, so their messages are
// deleted from now on, and leaves the API calls to a worker: the update loop never waits for them. a
// captcha already pending for the member is replaced
func (c *captcha) Start(user bot.User, lang string) {
	p := &pendingCaptcha{user: user, chatID: c.chatID, lang: lang}
	c.register(c.pending, p)
	c.running.Add(1)
	go c.verify(p)
}

// verify runs a pending captcha up to the posted challenge. ban mode: a member in a failure cooldown is banned
// for the rest of it, before any status read. administrators and members restricted by anyone but the join
// mute are left alone. an unknown status verifies anyway, except a member muted for good, muted for good
// again (mute mode). the timeout starts once the challenge is posted
func (c *captcha) verify(p *pendingCaptcha) {
	defer c.running.Done()
	c.workers <- struct{}{}
	defer func() { <-c.workers }()

	user := p.user
	if !c.isCurrent(c.pending, p) {
		return
	}
	if left := c.cooldownLeft(user.ID); left > 0 && !c.timeoutMute {
		if c.take(c.pending, user.ID, p) == nil {
			return
		}
		if err := c.remove(user, left, "rejoined during captcha cooldown"); err != nil {
			log.Printf("[WARN] %v", err)
		}
		return
	}

	status, err := c.memberStatus(user.ID)
	switch {
	case err != nil && c.timeoutMute && c.mutedForGood(user.ID):
		if c.take(c.pending, user.ID, p) == nil {
			return
		}
		log.Printf("[WARN] can't get member status of %s, muted for good before: %v", user, err)
		c.muteForeverOrBan(user, "status unknown after a permanent mute")
		return
	case err != nil:
		log.Printf("[WARN] can't get member status of %s, verifying anyway: %v", user, err)
	case status == "restricted" && !c.isMutedByCaptcha(user.ID):
		c.take(c.pending, user.ID, p)
		log.Printf("[INFO] %s is restricted already, captcha skipped", user)
		return
	case status != "member" && status != "restricted":
		c.take(c.pending, user.ID, p)
		log.Printf("[INFO] %s is %s, captcha skipped", user, status)
		return
	}

	if !c.isCurrent(c.pending, p) {
		return
	}
	if merr := c.mute(user, c.timeout+captchaGrace); merr != nil {
		c.take(c.pending, user.ID, p)
		log.Printf("[WARN] failed to mute %s for captcha, not verified: %v", user, merr)
		return
	}

	sent, code, page, err := c.challenge(c.chatID, p)
	if err != nil {
		if c.take(c.pending, user.ID, p) != nil {
			c.unmute(user)
		}
		log.Printf("[WARN] failed to send captcha to %s, unmuted: %v", user, err)
		return
	}

	if !c.posted(c.pending, p, sent.MessageID, code, page, c.expire) {
		return
	}
	log.Printf("[INFO] captcha sent to %s, timeout %v", user, c.timeout)
}

// HandleCallback processes a press on a candidate number. only the member the captcha was sent to can solve
// it, and the first press decides
func (c *captcha) HandleCallback(query *tbapi.CallbackQuery) error {
	lang := callbackLang(query)
	userID, choice, err := parseCaptchaData(query.Data)
	if err != nil {
		answerCallback(c.tbAPI, query.ID, captchaText(lang, txtExpired))
		return err
	}
	if query.From == nil || query.From.ID != userID {
		answerCallback(c.tbAPI, query.ID, captchaText(lang, txtOtherUser))
		return nil
	}
	// a press in the primary chat solves a join captcha, one in the member's private chat a test
	var pending map[int64]*pendingCaptcha
	test := false
	switch {
	case query.Message == nil:
	case query.Message.Chat.ID == c.chatID:
		pending = c.pending
	case query.Message.Chat.ID == userID:
		pending, test = c.tests, true
	}
	if pending == nil {
		answerCallback(c.tbAPI, query.ID, captchaText(lang, txtExpired))
		return nil
	}

	c.mu.Lock()
	p, ok := pending[userID]
	if !ok || p.msgID != query.Message.MessageID {
		c.mu.Unlock()
		answerCallback(c.tbAPI, query.ID, captchaText(lang, txtExpired))
		return nil
	}
	p.chosen = choice
	delete(pending, userID)
	c.forgetNonce(p)
	stopTimer(p)
	c.mu.Unlock()

	deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	if test {
		c.finishTest(query.ID, p)
		return nil
	}
	if p.chosen != p.code {
		answerCallback(c.tbAPI, query.ID, captchaText(lang, txtWrong))
		return c.fail(p.user, "wrong answer", true)
	}
	answerCallback(c.tbAPI, query.ID, captchaText(lang, txtVerified))
	c.solved(p)
	return nil
}

// solved lets in a member who passed the join captcha: failures are cleared and the mute lifted
func (c *captcha) solved(p *pendingCaptcha) {
	c.mu.Lock()
	delete(c.failures, p.user.ID)
	c.mu.Unlock()
	c.unmute(p.user)
	log.Printf("[INFO] captcha solved by %s", p.user)
}

// texts the bot shows members itself, by language; the prompt in the chat is --captcha.message
const (
	txtExpired = iota
	txtOtherUser
	txtVerified
	txtWrong
	txtDisabled
	txtTestPassed
	txtTestFailed      // chosen, code, first cooldown
	txtTestTimeout     // timeout, code
	txtTestTimeoutPage // timeout
	txtTestError       // error
	txtVerifyButton
	txtPageTitle
	txtPageHint
	txtPageDone
	txtPageFailed
	txtPageExpired
	txtPageLogin
	txtPromptMotion    // default caption of the animation, with {user} and {timeout}
	txtPromptTurnstile // default caption of the turnstile button
)

var captchaTexts = map[string][]string{
	"en": { //nolint:gosec // user-facing texts, not credentials
		txtExpired:    "this verification has expired",
		txtOtherUser:  "this verification is for another user",
		txtVerified:   "verified",
		txtWrong:      "wrong answer",
		txtDisabled:   "captcha is disabled",
		txtTestPassed: "captcha test passed, a member passing it would be let in",
		txtTestFailed: "captcha test failed: chose %s, the number was %s. a member would be removed for %s, " +
			"doubling with each further failure (test only, nothing happened to you)",
		txtTestTimeout: "captcha test timed out after %s, the number was %s. a member would be removed " +
			"(test only, nothing happened to you)",
		txtTestError:    "captcha test failed: %s",
		txtVerifyButton: "Verify",
		txtPageTitle:    "Verification",
		txtPageHint:     "Complete the check below to be let into the chat.",
		txtPageDone:     "Verified. You can go back to Telegram.",
		txtPageFailed:   "The check did not pass. Please try again.",
		txtPageExpired:  "This verification has expired or is already done.",
		txtPageLogin:    "Open this page with the button in Telegram and allow the login, it tells the bot who you are.",
		txtPromptMotion: "{user}, choose the number moving in the animation within {timeout}, otherwise you will be " +
			"removed from the chat. Tap the animation if it does not play.",
		txtPromptTurnstile: "{user}, press the button below and complete the check within {timeout}, " +
			"otherwise you will be removed from the chat.",
		txtTestTimeoutPage: "captcha test timed out after %s. a member would be removed (test only, nothing happened to you)",
	},
	"zh": { //nolint:gosec // user-facing texts, not credentials
		txtExpired:         "此验证已失效",
		txtOtherUser:       "这不是你的验证",
		txtVerified:        "验证通过",
		txtWrong:           "答案错误",
		txtDisabled:        "入群验证未启用",
		txtTestPassed:      "验证测试通过，成员这样操作会被放行",
		txtTestFailed:      "验证测试未通过：选择了 %s，正确答案是 %s。成员会被移出 %s，之后每次失败时长翻倍（仅为测试，你不受影响）",
		txtTestTimeout:     "验证测试已超时（%s），正确答案是 %s。成员会被移出（仅为测试，你不受影响）",
		txtTestError:       "验证测试失败：%s",
		txtVerifyButton:    "点击验证",
		txtPageTitle:       "入群验证",
		txtPageHint:        "完成下方验证后即可在群里发言。",
		txtPageDone:        "验证通过，可以返回 Telegram 了。",
		txtPageFailed:      "验证未通过，请重试。",
		txtPageExpired:     "此验证已失效或已完成。",
		txtPageLogin:       "请在 Telegram 里点按钮打开此页面，并允许登录，bot 需要据此确认你的身份。",
		txtPromptMotion:    "{user}，请在 {timeout} 内选择动图中移动的数字，否则会被移出群组。动图不动请点一下。",
		txtPromptTurnstile: "{user}，请在 {timeout} 内点击下方按钮完成验证，否则会被移出群组。",
		txtTestTimeoutPage: "验证测试已超时（%s）。成员会被移出（仅为测试，你不受影响）",
	},
	"ru": { //nolint:gosec // user-facing texts, not credentials
		txtExpired:    "эта проверка устарела",
		txtOtherUser:  "эта проверка для другого пользователя",
		txtVerified:   "проверка пройдена",
		txtWrong:      "неверный ответ",
		txtDisabled:   "проверка новых участников отключена",
		txtTestPassed: "тест пройден, участник с таким результатом был бы допущен",
		txtTestFailed: "тест не пройден: выбрано %s, верное число %s. участник был бы удалён на %s, " +
			"при каждой следующей ошибке срок удваивается (это только тест, вас это не затронуло)",
		txtTestTimeout: "время теста истекло (%s), верное число %s. участник был бы удалён " +
			"(это только тест, вас это не затронуло)",
		txtTestError:    "тест не удался: %s",
		txtVerifyButton: "Пройти проверку",
		txtPageTitle:    "Проверка",
		txtPageHint:     "Пройдите проверку ниже, чтобы писать в чате.",
		txtPageDone:     "Проверка пройдена. Можно вернуться в Telegram.",
		txtPageFailed:   "Проверка не пройдена. Попробуйте ещё раз.",
		txtPageExpired:  "Эта проверка устарела или уже пройдена.",
		txtPageLogin:    "Откройте эту страницу кнопкой в Telegram и разрешите вход, так бот узнает, кто вы.",
		txtPromptMotion: "{user}, выберите число, которое движется на анимации, в течение {timeout}, иначе вы будете " +
			"удалены из чата. Нажмите на анимацию, если она не воспроизводится.",
		txtPromptTurnstile: "{user}, нажмите кнопку ниже и пройдите проверку в течение {timeout}, иначе вы будете " +
			"удалены из чата.",
		txtTestTimeoutPage: "время теста истекло (%s). участник был бы удалён (это только тест, вас это не затронуло)",
	},
}

// callbackLang returns the telegram language of whoever pressed a button
func callbackLang(query *tbapi.CallbackQuery) string {
	if query.From == nil {
		return ""
	}
	return query.From.LanguageCode
}

// captchaText returns the text in the member's telegram language ("zh-hans" uses "zh"), english when missing
func captchaText(lang string, id int, args ...any) string {
	lang, _, _ = strings.Cut(strings.ToLower(lang), "-")
	texts, ok := captchaTexts[lang]
	if !ok {
		texts = captchaTexts["en"]
	}
	if len(args) == 0 {
		return texts[id]
	}
	return fmt.Sprintf(texts[id], args...)
}

// IsPending reports whether the member has an unsolved captcha
func (c *captcha) IsPending(userID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.pending[userID]
	return ok
}

// Cancel drops the captcha of a member who has left the chat. once the challenge was posted it counts as a
// failure, which in the ban mode makes a rejoin run into the cooldown; nobody is banned, the member is gone
func (c *captcha) Cancel(userID int64) {
	p := c.take(c.pending, userID, nil)
	if p == nil {
		return
	}
	deleteMessage(c.tbAPI, c.chatID, p.msgID, "captcha")
	if p.msgID == 0 {
		return // left before the challenge was posted, nothing was failed
	}
	if err := c.fail(p.user, "left the chat", false); err != nil {
		log.Printf("[WARN] %v", err)
	}
}

// Stop cancels all pending captchas and deletes their messages, waiting for verifications in progress.
// members under the join mute are released by its expiry; permanent mutes from timeouts are not touched
func (c *captcha) Stop() {
	c.mu.Lock()
	posted := make([]*pendingCaptcha, 0, len(c.pending)+len(c.tests))
	for _, m := range []map[int64]*pendingCaptcha{c.pending, c.tests} {
		for id, p := range m {
			stopTimer(p)
			posted = append(posted, p)
			delete(m, id)
		}
	}
	clear(c.nonces)
	c.mu.Unlock()
	c.running.Wait() // verifications find their captcha gone and delete what they posted
	for _, p := range posted {
		deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	}
}

// StartTest posts a test challenge to a member in their private chat with the bot, so the animation can be
// checked in real clients. the caption is the join captcha's own. nothing happens to the member: no mute, no
// ban, no failure count; the result is told in the private chat. a test already pending is replaced
func (c *captcha) StartTest(user bot.User, lang string) {
	p := &pendingCaptcha{user: user, chatID: user.ID, lang: lang}
	c.register(c.tests, p)
	c.running.Add(1)
	go c.postTest(p)
}

func (c *captcha) postTest(p *pendingCaptcha) {
	defer c.running.Done()
	c.workers <- struct{}{}
	defer func() { <-c.workers }()

	if !c.isCurrent(c.tests, p) {
		return // replaced by a newer test, don't render this one
	}
	sent, code, page, err := c.challenge(p.chatID, p)
	if err != nil {
		log.Printf("[WARN] failed to send captcha test to %s: %v", p.user, err)
		if c.take(c.tests, p.user.ID, p) != nil {
			c.sendText(p.chatID, captchaText(p.lang, txtTestError, redactBotToken(err.Error())))
		}
		return
	}
	if c.posted(c.tests, p, sent.MessageID, code, page, c.expireTest) {
		log.Printf("[INFO] captcha test sent to %s", p.user)
	}
}

func (c *captcha) expireTest(p *pendingCaptcha) {
	if c.take(c.tests, p.user.ID, p) == nil {
		return
	}
	deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	if p.page {
		c.sendText(p.chatID, captchaText(p.lang, txtTestTimeoutPage, compactDuration(c.timeout)))
		return
	}
	c.sendText(p.chatID, captchaText(p.lang, txtTestTimeout, compactDuration(c.timeout), p.code))
}

// finishTest tells the member how a completed test went
func (c *captcha) finishTest(queryID string, p *pendingCaptcha) {
	if p.chosen == p.code {
		answerCallback(c.tbAPI, queryID, captchaText(p.lang, txtVerified))
		c.sendText(p.chatID, captchaText(p.lang, txtTestPassed))
		return
	}
	answerCallback(c.tbAPI, queryID, captchaText(p.lang, txtWrong))
	c.sendText(p.chatID, captchaText(p.lang, txtTestFailed, p.chosen, p.code, compactDuration(captchaCooldown)))
}

func (c *captcha) sendText(chatID int64, text string) {
	if _, err := c.tbAPI.Send(tbapi.NewMessage(chatID, text)); err != nil {
		log.Printf("[WARN] failed to send captcha message to %d: %v", chatID, err)
	}
}

func (c *captcha) expire(p *pendingCaptcha) {
	if c.take(c.pending, p.user.ID, p) == nil {
		return // solved, replaced or canceled in the meantime
	}
	deleteMessage(c.tbAPI, c.chatID, p.msgID, "captcha")
	if err := c.fail(p.user, "timeout", !c.timeoutMute); err != nil {
		log.Printf("[WARN] %v", err)
	}
	if c.timeoutMute {
		c.muteForeverOrBan(p.user, "captcha timeout")
	}
}

// muteForeverOrBan mutes the member for good, or bans them for the cooldown if telegram refuses: the join mute
// ends a minute after the timeout, and a member must not be left free to post unverified
func (c *captcha) muteForeverOrBan(user bot.User, reason string) {
	err := c.muteForever(user)
	if err == nil {
		log.Printf("[INFO] %s muted for good, %s", user, reason)
		return
	}
	d := max(c.cooldownLeft(user.ID), captchaCooldown)
	berr := c.ban(user, d)
	if berr == nil {
		log.Printf("[WARN] failed to mute %s for good, %s, banned for %v instead: %v", user, reason, d.Round(time.Second), err)
		return
	}
	// last resort, keeps the member from posting at least for the cooldown
	if merr := c.mute(user, d); merr != nil {
		log.Printf("[WARN] failed to mute %s for good, %s: %v, to ban: %v, and to mute: %v", user, reason, err, berr, merr)
		return
	}
	log.Printf("[WARN] failed to mute %s for good, %s, and to ban, muted for %v: %v; %v", user, reason,
		d.Round(time.Second), err, berr)
}

// mutedForGood reports whether the member's last, not forgotten failure muted them for good
func (c *captcha) mutedForGood(userID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.failure(userID)
	return ok && f.forever
}

// register makes p the member's captcha in m (pending or tests), deleting the one it replaces
func (c *captcha) register(m map[int64]*pendingCaptcha, p *pendingCaptcha) {
	c.mu.Lock()
	prev := m[p.user.ID]
	m[p.user.ID] = p
	prevMsgID, prevChatID := 0, int64(0)
	if prev != nil {
		prevMsgID, prevChatID = prev.msgID, prev.chatID
		stopTimer(prev)
		c.forgetNonce(prev)
	}
	c.mu.Unlock()
	deleteMessage(c.tbAPI, prevChatID, prevMsgID, "captcha")
}

// posted records the sent challenge on p and starts its timeout, if p is still the member's captcha in m.
// otherwise the challenge was resolved while being sent, its message is deleted and posted returns false
func (c *captcha) posted(m map[int64]*pendingCaptcha, p *pendingCaptcha, msgID int, code string, page bool,
	onTimeout func(*pendingCaptcha)) bool {
	c.mu.Lock()
	current := m[p.user.ID] == p
	if current {
		p.msgID, p.code, p.page = msgID, code, page
		p.timer = time.AfterFunc(c.timeout, func() { onTimeout(p) })
		if page {
			c.nonces[code] = p
		}
	}
	c.mu.Unlock()
	if !current {
		deleteMessage(c.tbAPI, p.chatID, msgID, "captcha")
	}
	return current
}

// take removes the member's captcha from m (pending or tests) and returns it. with want set, only that
// exact entry is taken
func (c *captcha) take(m map[int64]*pendingCaptcha, userID int64, want *pendingCaptcha) *pendingCaptcha {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := m[userID]
	if !ok || (want != nil && p != want) {
		return nil
	}
	delete(m, userID)
	stopTimer(p)
	c.forgetNonce(p)
	return p
}

// forgetNonce drops the page of a Turnstile captcha, call with mu held
func (c *captcha) forgetNonce(p *pendingCaptcha) {
	if p.page && c.nonces[p.code] == p {
		delete(c.nonces, p.code)
	}
}

// challenge posts the challenge for p in chatID: the animation with candidate buttons, or in Turnstile mode
// a button opening the challenge page. it returns the sent message and the code, the number or the nonce
// with page set, so only a page nonce is registered as one
func (c *captcha) challenge(chatID int64, p *pendingCaptcha) (sent tbapi.Message, code string, page bool, err error) {
	if c.turnstile != nil && !c.turnstile.refused.Load() {
		nonce := newNonce()
		sent, err = c.sendTurnstile(chatID, nonce, c.prompt(p), p.lang)
		if err == nil {
			return sent, nonce, true, nil
		}
		// a login button is refused while the bot's domain is not set; falling back keeps members verified,
		// and remembering the refusal spares a failing send per join until a restart
		if strings.Contains(err.Error(), "BOT_DOMAIN_INVALID") && !c.turnstile.refused.Swap(true) {
			log.Printf("[ERROR] telegram refuses the turnstile login button, set the bot domain with @BotFather "+
				"/setdomain and restart; the animation is used until then: %v", err)
		} else {
			log.Printf("[WARN] turnstile button for %s failed, falling back to the animation: %v", p.user, err)
		}
	}
	code = newCaptchaCode()
	sent, err = c.send(chatID, p.user, code, c.motionPrompt(p))
	return sent, code, false, err
}

// isCurrent reports whether p is still the member's captcha in m
func (c *captcha) isCurrent(m map[int64]*pendingCaptcha, p *pendingCaptcha) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return m[p.user.ID] == p
}

// newCaptchaCode returns a random captchaCodeLen-digit number
func newCaptchaCode() string {
	code := make([]byte, captchaCodeLen)
	for i := range code {
		code[i] = byte('0' + rand.IntN(10)) //nolint:gosec // math/rand/v2 is seeded from the OS entropy
	}
	return string(code)
}

// stopTimer stops the timeout of a posted captcha, call with mu held
func stopTimer(p *pendingCaptcha) {
	if p.timer != nil {
		p.timer.Stop()
	}
}

// fail records a failed captcha and, with remove set, bans the member for the cooldown it earns
func (c *captcha) fail(user bot.User, reason string, remove bool) error {
	now := time.Now()
	c.mu.Lock()
	for id, f := range c.failures {
		if failureForgotten(f, now) {
			delete(c.failures, id)
		}
	}
	f := c.failures[user.ID]
	f.count++
	f.last = now
	f.forever = false // set by muteForever when this failure mutes for good
	c.failures[user.ID] = f
	c.mu.Unlock()

	log.Printf("[INFO] captcha failed by %s: %s, failure %d", user, reason, f.count)
	if !remove {
		return nil
	}
	return c.remove(user, cooldownFor(f.count), reason)
}

// cooldownLeft returns how long the member is still barred from a new captcha
func (c *captcha) cooldownLeft(userID int64) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.failure(userID)
	if !ok {
		return 0
	}
	return max(time.Until(f.last.Add(cooldownFor(f.count))), 0)
}

// failure returns the member's failure record unless it is forgotten, older than captchaMaxCooldown, the rule
// fail prunes by. call with mu held
func (c *captcha) failure(userID int64) (captchaFailure, bool) {
	f, ok := c.failures[userID]
	if !ok || failureForgotten(f, time.Now()) {
		return captchaFailure{}, false
	}
	return f, true
}

// failureForgotten reports whether a failure is old enough to be forgotten
func failureForgotten(f captchaFailure, now time.Time) bool {
	return now.Sub(f.last) > captchaMaxCooldown
}

// cooldownFor returns the ban duration after the given number of failures
func cooldownFor(failures int) time.Duration {
	d := captchaCooldown
	for i := 1; i < failures && d < captchaMaxCooldown; i++ {
		d *= 2
	}
	return min(d, captchaMaxCooldown)
}

// remove bans the member until the cooldown ends, telegram lifts the ban by itself then. if the ban fails
// the member is muted instead, for the cooldown, or for good in the mute mode: a failed captcha must not
// leave them free to post
func (c *captcha) remove(user bot.User, d time.Duration, reason string) error {
	err := c.ban(user, d)
	if err == nil {
		log.Printf("[INFO] %s removed for %v, captcha %s", user, d.Round(time.Second), reason)
		return nil
	}
	if c.timeoutMute {
		// a timed mute would end with the member in the chat, unverified, and the mute mode has no rejoin
		// cooldown to catch them; muted for good they read as restricted on a rejoin
		if merr := c.muteForever(user); merr != nil {
			return fmt.Errorf("failed to remove %s after captcha %s: %w, and to mute for good: %w", user, reason, err, merr)
		}
		return fmt.Errorf("failed to remove %s after captcha %s, muted for good instead: %w", user, reason, err)
	}
	if merr := c.mute(user, d); merr != nil {
		return fmt.Errorf("failed to remove %s after captcha %s: %w, and to mute: %w", user, reason, err, merr)
	}
	return fmt.Errorf("failed to remove %s after captcha %s, muted for %v instead: %w", user, reason, d, err)
}

// ban removes the member until d from now, telegram lifts the ban by itself. the join mute is gone with the
// ban, so its record is dropped: a restriction set later must not read as the captcha's own
func (c *captcha) ban(user bot.User, d time.Duration) error {
	if err := banUserOrChannel(banRequest{tbAPI: c.tbAPI, userID: user.ID, chatID: c.chatID, duration: d,
		userName: user.String()}); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.muted, user.ID)
	c.mu.Unlock()
	return nil
}

// mute is the join mute: every permission taken for d, expiring on its own so a member whose captcha is lost
// is not muted for good. it is recorded, telling it apart from other restrictions on rejoin
func (c *captcha) mute(user bot.User, d time.Duration) error {
	until := time.Now().Add(max(d, time.Minute)) // under 30 seconds is forever for telegram
	if err := c.restrict(user, until.Unix()); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, t := range c.muted {
		if t.Before(now) {
			delete(c.muted, id)
		}
	}
	c.muted[user.ID] = until
	return nil
}

// muteForever takes every permission from the member with no end. unlike mute it drops the member from muted,
// so the restriction is never taken for the captcha's own and lifted by a later captcha; an admin lifts it.
// the member's failure record gets forever, read by verify when the status is unknown
func (c *captcha) muteForever(user bot.User) error {
	if err := c.restrict(user, 0); err != nil { // 0 is forever for telegram
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.muted, user.ID)
	// marks the failure that led here; a record missing now was cleared by a solve, which leaves nothing to mark
	if f, ok := c.failures[user.ID]; ok {
		f.forever = true
		c.failures[user.ID] = f
	}
	return nil
}

// restrict takes every permission from the member until untilDate (unix seconds, 0 for good)
func (c *captcha) restrict(user bot.User, untilDate int64) error {
	return c.request(tbapi.RestrictChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: user.ID},
		UntilDate:        untilDate,
		Permissions:      &tbapi.ChatPermissions{},
	})
}

// isMutedByCaptcha reports whether the member's restriction is the captcha's own mute
func (c *captcha) isMutedByCaptcha(userID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.muted[userID]
	return ok && until.After(time.Now())
}

// unmute lifts the captcha mute. per the Bot API, passing true for all permissions lifts a restriction,
// the member is then a regular member bound by the chat's default permissions
func (c *captcha) unmute(user bot.User) {
	err := c.request(tbapi.RestrictChatMemberConfig{
		ChatMemberConfig:              tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: user.ID},
		UseIndependentChatPermissions: true,
		Permissions: &tbapi.ChatPermissions{CanSendMessages: true, CanSendAudios: true, CanSendDocuments: true,
			CanSendPhotos: true, CanSendVideos: true, CanSendVideoNotes: true, CanSendVoiceNotes: true,
			CanSendPolls: true, CanReactToMessages: true, CanSendOtherMessages: true, CanAddWebPagePreviews: true,
			CanEditTag: true, CanChangeInfo: true, CanInviteUsers: true, CanPinMessages: true, CanManageTopics: true},
	})
	if err != nil {
		log.Printf("[WARN] failed to unmute %s, the mute expires by itself: %v", user, err)
		return
	}
	c.mu.Lock()
	delete(c.muted, user.ID)
	c.mu.Unlock()
}

func (c *captcha) memberStatus(userID int64) (string, error) {
	resp, err := c.tbAPI.Request(tbapi.GetChatMemberConfig{ChatConfigWithUser: tbapi.ChatConfigWithUser{
		ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: userID}})
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	var member tbapi.ChatMember
	if err := json.Unmarshal(resp.Result, &member); err != nil {
		return "", fmt.Errorf("unmarshal chat member: %w", err)
	}
	return member.Status, nil
}

// send posts the animation with the caption and the candidate numbers, three per row
func (c *captcha) send(chatID int64, user bot.User, code, caption string) (tbapi.Message, error) {
	img, err := c.render(code)
	if err != nil {
		return tbapi.Message{}, err
	}
	choices := captchaCandidates(code)
	rows := make([][]tbapi.InlineKeyboardButton, 0, (len(choices)+2)/3)
	for i, choice := range choices {
		if i%3 == 0 {
			rows = append(rows, make([]tbapi.InlineKeyboardButton, 0, 3))
		}
		rows[len(rows)-1] = append(rows[len(rows)-1],
			tbapi.NewInlineKeyboardButtonData(choice, fmt.Sprintf("%s%d:%s", captchaPrefix, user.ID, choice)))
	}

	anim := tbapi.NewAnimation(chatID, tbapi.FileBytes{Name: "captcha.gif", Bytes: img})
	anim.Caption = caption
	anim.ParseMode = tbapi.ModeHTML
	anim.ReplyMarkup = tbapi.NewInlineKeyboardMarkup(rows...)
	msg, err := c.tbAPI.Send(anim)
	if err != nil {
		return tbapi.Message{}, fmt.Errorf("send animation: %w", err)
	}
	return msg, nil
}

// prompt is the caption of p's challenge: --captcha.message, or the mode's default in the member's language
func (c *captcha) prompt(p *pendingCaptcha) string {
	message := c.message
	switch {
	case message != "":
	case c.turnstile != nil:
		message = captchaText(p.lang, txtPromptTurnstile)
	default:
		message = captchaText(p.lang, txtPromptMotion)
	}
	return c.expandPrompt(p.user, message)
}

// motionPrompt is the caption of the animation. when the turnstile button falls back it is the animation's
// default in the member's language, since a prompt written for turnstile asks to press a button the
// animation doesn't have
func (c *captcha) motionPrompt(p *pendingCaptcha) string {
	if c.turnstile == nil {
		return c.prompt(p)
	}
	return c.expandPrompt(p.user, captchaText(p.lang, txtPromptMotion))
}

// expandPrompt fills the {user} mention and the {timeout} of a prompt template, escaped for HTML
func (c *captcha) expandPrompt(user bot.User, message string) string {
	name := user.DisplayName
	if name == "" {
		name = user.Username
	}
	if name == "" {
		name = strconv.FormatInt(user.ID, 10)
	}
	mention := fmt.Sprintf(`<a href="tg://user?id=%d">%s</a>`, user.ID, html.EscapeString(name))
	return strings.NewReplacer("{user}", mention, "{timeout}", compactDuration(c.timeout)).
		Replace(html.EscapeString(message))
}

func (c *captcha) request(cfg tbapi.Chattable) error {
	resp, err := c.tbAPI.Request(cfg)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if !resp.Ok {
		return fmt.Errorf("response is not Ok: %s", string(resp.Result))
	}
	return nil
}

func parseCaptchaData(data string) (userID int64, key string, err error) {
	idStr, key, ok := strings.Cut(strings.TrimPrefix(data, captchaPrefix), ":")
	if !ok {
		return 0, "", fmt.Errorf("invalid captcha callback data %q", data)
	}
	if userID, err = strconv.ParseInt(idStr, 10, 64); err != nil {
		return 0, "", fmt.Errorf("invalid user ID in captcha callback data %q: %w", data, err)
	}
	if len(key) != captchaCodeLen || strings.Trim(key, "0123456789") != "" {
		return 0, "", fmt.Errorf("invalid choice in captcha callback data %q", data)
	}
	return userID, key, nil
}

// captchaCandidates returns captchaChoices distinct numbers in random order, the code among them. the
// others are random and independent of the code: decoys derived from it (swapped digits, a digit off by one)
// would make the code the one candidate closest to all the others, readable from the buttons alone
func captchaCandidates(code string) []string {
	res := make([]string, 0, captchaChoices)
	res = append(res, code)
	for len(res) < captchaChoices {
		if c := newCaptchaCode(); !slices.Contains(res, c) {
			res = append(res, c)
		}
	}
	rand.Shuffle(len(res), func(i, j int) { res[i], res[j] = res[j], res[i] }) //nolint:gosec // layout
	return res
}

// compactDuration formats a duration without zero tails, 2m instead of 2m0s and 1h instead of 1h0m0s
func compactDuration(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
