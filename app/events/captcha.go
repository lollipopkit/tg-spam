package events

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"

	"github.com/umputun/tg-spam/app/bot"
)

// captchaPrefix marks callback data of captcha buttons, "C<userID>:<key>" with key a digit or captchaBackspace
const captchaPrefix = "C"

const (
	captchaCodeLen   = 3
	captchaBackspace = "b"
	captchaWorkers   = 4 // concurrent verifications, each makes a few API calls, renders and uploads

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
// shows a number only in motion (see renderMotionCaptcha) with a shuffled keypad under it. entering the
// number lifts the mute. a wrong number, the timeout or leaving with the captcha unsolved is a failure:
// the member is banned for a cooldown that doubles with each failure, so guessing by rejoining stays slow.
// safe for concurrent use: callbacks come from the update loop, timeouts from timer goroutines and the
// verification itself from worker goroutines.
type captcha struct {
	tbAPI   TbAPI
	chatID  int64
	timeout time.Duration
	message string                            // prompt template with {user} and {timeout} placeholders
	render  func(code string) ([]byte, error) // draws the challenge image

	workers chan struct{}  // limits concurrent verifications
	running sync.WaitGroup // verifications in progress, waited for by Stop

	mu       sync.Mutex
	pending  map[int64]*pendingCaptcha // by user ID
	tests    map[int64]*pendingCaptcha // test challenges in private chats, by user ID
	failures map[int64]captchaFailure  // by user ID
	muted    map[int64]time.Time       // members under the captcha's own mute, by user ID, to its expiry
}

type pendingCaptcha struct {
	user    bot.User
	chatID  int64  // chat the challenge is posted in
	msgID   int    // captcha message, 0 until posted
	code    string // the number to enter, set when posted
	entered string // digits pressed so far
	timer   *time.Timer
}

type captchaFailure struct {
	count int
	last  time.Time
}

func newCaptcha(tbAPI TbAPI, chatID int64, timeout time.Duration, message string) *captcha {
	return &captcha{tbAPI: tbAPI, chatID: chatID, timeout: timeout, message: message, render: renderMotionCaptcha,
		workers: make(chan struct{}, captchaWorkers), pending: make(map[int64]*pendingCaptcha),
		tests: make(map[int64]*pendingCaptcha), failures: make(map[int64]captchaFailure),
		muted: make(map[int64]time.Time)}
}

// Start verifies a member who has just joined. it only marks the member pending, so their messages are
// deleted from now on, and leaves the API calls to a worker: the update loop never waits for them. a
// captcha already pending for the member is replaced
func (c *captcha) Start(user bot.User) {
	p := &pendingCaptcha{user: user, chatID: c.chatID}
	c.register(c.pending, p)
	c.running.Add(1)
	go c.verify(p)
}

// verify runs a pending captcha up to the posted challenge. a member still in a failure cooldown is banned
// for the rest of it. administrators and members restricted by anyone but the captcha are left alone: muting
// a restricted member would replace a soft ban or an admin mute with one that expires. with the status
// unknown the member is verified anyway. the timeout starts once the challenge is posted, a member waiting
// for a worker can't time out before seeing it
func (c *captcha) verify(p *pendingCaptcha) {
	defer c.running.Done()
	c.workers <- struct{}{}
	defer func() { <-c.workers }()

	user := p.user
	if !c.isCurrent(c.pending, p) {
		return
	}
	if left := c.cooldownLeft(user.ID); left > 0 {
		c.take(c.pending, user.ID, p)
		if err := c.remove(user, left, "rejoined during captcha cooldown"); err != nil {
			log.Printf("[WARN] %v", err)
		}
		return
	}

	status, err := c.memberStatus(user.ID)
	switch {
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

	code := newCaptchaCode()
	sent, err := c.send(c.chatID, user, code, c.prompt(user))
	if err != nil {
		if c.take(c.pending, user.ID, p) != nil {
			c.unmute(user)
		}
		log.Printf("[WARN] failed to send captcha to %s, unmuted: %v", user, err)
		return
	}

	if !c.posted(c.pending, p, sent.MessageID, code, c.expire) {
		return
	}
	log.Printf("[INFO] captcha sent to %s, timeout %v", user, c.timeout)
}

// HandleCallback processes a keypad press. only the member the captcha was sent to can solve it. the
// number is checked once all its digits are entered, so a wrong digit gives nothing away
func (c *captcha) HandleCallback(query *tbapi.CallbackQuery) error {
	userID, key, err := parseCaptchaData(query.Data)
	if err != nil {
		answerCallback(c.tbAPI, query.ID, captchaExpired)
		return err
	}
	if query.From == nil || query.From.ID != userID {
		answerCallback(c.tbAPI, query.ID, "this verification is for another user")
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
		answerCallback(c.tbAPI, query.ID, captchaExpired)
		return nil
	}

	c.mu.Lock()
	p, ok := pending[userID]
	if !ok || p.msgID != query.Message.MessageID {
		c.mu.Unlock()
		answerCallback(c.tbAPI, query.ID, captchaExpired)
		return nil
	}
	if key == captchaBackspace {
		if p.entered != "" {
			p.entered = p.entered[:len(p.entered)-1]
		}
	} else {
		p.entered += key
	}
	if len(p.entered) < len(p.code) {
		progress := strings.Repeat("● ", len(p.entered)) + strings.Repeat("○ ", len(p.code)-len(p.entered))
		c.mu.Unlock()
		answerCallback(c.tbAPI, query.ID, strings.TrimSpace(progress))
		return nil
	}
	delete(pending, userID)
	stopTimer(p)
	c.mu.Unlock()

	deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	if test {
		c.finishTest(query.ID, p)
		return nil
	}
	if p.entered != p.code {
		answerCallback(c.tbAPI, query.ID, "wrong answer")
		return c.fail(p.user, "wrong answer", true)
	}
	answerCallback(c.tbAPI, query.ID, "verified")
	c.mu.Lock()
	delete(c.failures, userID)
	c.mu.Unlock()
	c.unmute(p.user)
	log.Printf("[INFO] captcha solved by %s", p.user)
	return nil
}

// captchaExpired answers a press on a captcha that is no longer pending
const captchaExpired = "this verification has expired"

// IsPending reports whether the member has an unsolved captcha
func (c *captcha) IsPending(userID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.pending[userID]
	return ok
}

// Cancel drops the captcha of a member who has left the chat. it counts as a failure, so leaving and
// rejoining for a fresh challenge runs into the cooldown, but nobody is banned since the member is gone
func (c *captcha) Cancel(userID int64) {
	p := c.take(c.pending, userID, nil)
	if p == nil {
		return
	}
	deleteMessage(c.tbAPI, c.chatID, p.msgID, "captcha")
	if err := c.fail(p.user, "left the chat", false); err != nil {
		log.Printf("[WARN] %v", err)
	}
}

// Stop cancels all pending captchas and deletes their messages, waiting for verifications in progress.
// the muted members are released by their mute expiry
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
	c.mu.Unlock()
	c.running.Wait() // verifications find their captcha gone and delete what they posted
	for _, p := range posted {
		deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	}
}

// StartTest posts a test challenge to a member in their private chat with the bot, so the animation can be
// checked in real clients. the caption is the join captcha's own. nothing happens to the member: no mute, no
// ban, no failure count; the result is told in the private chat. a test already pending is replaced
func (c *captcha) StartTest(user bot.User) {
	p := &pendingCaptcha{user: user, chatID: user.ID}
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
	code := newCaptchaCode()
	sent, err := c.send(p.chatID, p.user, code, c.prompt(p.user))
	if err != nil {
		log.Printf("[WARN] failed to send captcha test to %s: %v", p.user, err)
		if c.take(c.tests, p.user.ID, p) != nil {
			c.sendText(p.chatID, "captcha test failed: "+redactBotToken(err.Error()))
		}
		return
	}
	if c.posted(c.tests, p, sent.MessageID, code, c.expireTest) {
		log.Printf("[INFO] captcha test sent to %s", p.user)
	}
}

func (c *captcha) expireTest(p *pendingCaptcha) {
	if c.take(c.tests, p.user.ID, p) == nil {
		return
	}
	deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	c.sendText(p.chatID, fmt.Sprintf("captcha test timed out after %s, the number was %s. "+
		"a member would be removed (test only, nothing happened to you)", compactDuration(c.timeout), p.code))
}

// finishTest tells the member how a completed test went
func (c *captcha) finishTest(queryID string, p *pendingCaptcha) {
	if p.entered == p.code {
		answerCallback(c.tbAPI, queryID, "verified")
		c.sendText(p.chatID, "captcha test passed, a member entering this would be let in")
		return
	}
	answerCallback(c.tbAPI, queryID, "wrong answer")
	c.sendText(p.chatID, fmt.Sprintf("captcha test failed: entered %s, the number was %s. a member would be "+
		"removed for %s, doubling with each further failure (test only, nothing happened to you)",
		p.entered, p.code, compactDuration(captchaCooldown)))
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
	if err := c.fail(p.user, "timeout", true); err != nil {
		log.Printf("[WARN] %v", err)
	}
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
	}
	c.mu.Unlock()
	deleteMessage(c.tbAPI, prevChatID, prevMsgID, "captcha")
}

// posted records the sent challenge on p and starts its timeout, if p is still the member's captcha in m.
// otherwise the challenge was resolved while being sent, its message is deleted and posted returns false
func (c *captcha) posted(m map[int64]*pendingCaptcha, p *pendingCaptcha, msgID int, code string,
	onTimeout func(*pendingCaptcha)) bool {
	c.mu.Lock()
	current := m[p.user.ID] == p
	if current {
		p.msgID, p.code = msgID, code
		p.timer = time.AfterFunc(c.timeout, func() { onTimeout(p) })
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
	return p
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
		if now.Sub(f.last) > captchaMaxCooldown {
			delete(c.failures, id)
		}
	}
	f := c.failures[user.ID]
	f.count++
	f.last = now
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
	f, ok := c.failures[userID]
	if !ok {
		return 0
	}
	return max(time.Until(f.last.Add(cooldownFor(f.count))), 0)
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
// the member is muted for the cooldown instead, a failed captcha must not leave them free to post
func (c *captcha) remove(user bot.User, d time.Duration, reason string) error {
	err := banUserOrChannel(banRequest{tbAPI: c.tbAPI, userID: user.ID, chatID: c.chatID, duration: d,
		userName: user.String()})
	if err == nil {
		log.Printf("[INFO] %s removed for %v, captcha %s", user, d.Round(time.Second), reason)
		return nil
	}
	if merr := c.mute(user, d); merr != nil {
		return fmt.Errorf("failed to remove %s after captcha %s: %w, and to mute: %w", user, reason, err, merr)
	}
	return fmt.Errorf("failed to remove %s after captcha %s, muted for %v instead: %w", user, reason, d, err)
}

// mute takes every permission from the member for d. the mute expires on its own, so a member whose
// captcha is lost is not muted for good. it is recorded, telling it apart from other restrictions on rejoin
func (c *captcha) mute(user bot.User, d time.Duration) error {
	until := time.Now().Add(max(d, time.Minute)) // under 30 seconds is forever for telegram
	err := c.request(tbapi.RestrictChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: user.ID},
		UntilDate:        until.Unix(),
		Permissions:      &tbapi.ChatPermissions{},
	})
	if err != nil {
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

// send posts the animation with the caption and a keypad of shuffled digits and a backspace
func (c *captcha) send(chatID int64, user bot.User, code, caption string) (tbapi.Message, error) {
	img, err := c.render(code)
	if err != nil {
		return tbapi.Message{}, err
	}
	button := func(key, label string) tbapi.InlineKeyboardButton {
		return tbapi.NewInlineKeyboardButtonData(label, fmt.Sprintf("%s%d:%s", captchaPrefix, user.ID, key))
	}
	digits := rand.Perm(10) //nolint:gosec // layout, not a secret
	rows := make([][]tbapi.InlineKeyboardButton, 0, 3)
	for r := range 3 {
		row := make([]tbapi.InlineKeyboardButton, 0, 4)
		for _, d := range digits[r*4 : min(r*4+4, 10)] {
			row = append(row, button(strconv.Itoa(d), strconv.Itoa(d)))
		}
		rows = append(rows, row)
	}
	rows[2] = append(rows[2], button(captchaBackspace, "⌫"))

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

func (c *captcha) prompt(user bot.User) string {
	name := user.DisplayName
	if name == "" {
		name = user.Username
	}
	if name == "" {
		name = strconv.FormatInt(user.ID, 10)
	}
	mention := fmt.Sprintf(`<a href="tg://user?id=%d">%s</a>`, user.ID, html.EscapeString(name))
	return strings.NewReplacer("{user}", mention, "{timeout}", compactDuration(c.timeout)).
		Replace(html.EscapeString(c.message))
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
	if key != captchaBackspace && (len(key) != 1 || key[0] < '0' || key[0] > '9') {
		return 0, "", fmt.Errorf("invalid key in captcha callback data %q", data)
	}
	return userID, key, nil
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
