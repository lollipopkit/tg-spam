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
	captchaSenders   = 4 // concurrent renders and uploads, the update loop never waits for them

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
// safe for concurrent use: callbacks come from the update loop, timeouts from timer goroutines and posting
// from sender goroutines.
type captcha struct {
	tbAPI   TbAPI
	chatID  int64
	timeout time.Duration
	message string                            // prompt template with {user} and {timeout} placeholders
	render  func(code string) ([]byte, error) // draws the challenge image

	senders chan struct{}  // limits concurrent posting
	posting sync.WaitGroup // in-flight posts, waited for by Stop

	mu       sync.Mutex
	pending  map[int64]*pendingCaptcha // by user ID
	failures map[int64]captchaFailure  // by user ID
}

type pendingCaptcha struct {
	user    bot.User
	msgID   int    // captcha message, 0 until posted
	code    string // the number to enter
	entered string // digits pressed so far
	timer   *time.Timer
}

type captchaFailure struct {
	count int
	last  time.Time
}

func newCaptcha(tbAPI TbAPI, chatID int64, timeout time.Duration, message string) *captcha {
	return &captcha{tbAPI: tbAPI, chatID: chatID, timeout: timeout, message: message, render: renderMotionCaptcha,
		senders: make(chan struct{}, captchaSenders), pending: make(map[int64]*pendingCaptcha),
		failures: make(map[int64]captchaFailure)}
}

// Start verifies a member who has just joined. a member already restricted (soft-banned or muted by an
// admin) is left alone, so rejoining can't lift a restriction. a member still in a failure cooldown is
// banned for the rest of it without a challenge. otherwise the member is muted and the challenge is posted
// in the background; a challenge already pending for the member is replaced
func (c *captcha) Start(user bot.User) error {
	status, err := c.memberStatus(user.ID)
	if err != nil {
		return fmt.Errorf("failed to get member status of %s for captcha: %w", user, err)
	}
	if status == "restricted" {
		log.Printf("[INFO] %s is restricted already, captcha skipped", user)
		return nil
	}
	if left := c.cooldownLeft(user.ID); left > 0 {
		return c.ban(user, left, "rejoined during captcha cooldown")
	}

	mute := tbapi.RestrictChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: user.ID},
		UntilDate:        time.Now().Add(c.timeout + captchaGrace).Unix(),
		Permissions:      &tbapi.ChatPermissions{},
	}
	if err := c.request(mute); err != nil {
		return fmt.Errorf("failed to mute %s for captcha: %w", user, err)
	}

	code := make([]byte, captchaCodeLen)
	for i := range code {
		code[i] = byte('0' + rand.IntN(10)) //nolint:gosec // math/rand/v2 is seeded from the OS entropy
	}
	p := &pendingCaptcha{user: user, code: string(code)}
	c.mu.Lock()
	prev := c.pending[user.ID]
	c.pending[user.ID] = p
	p.timer = time.AfterFunc(c.timeout, func() { c.expire(p) })
	c.mu.Unlock()
	if prev != nil {
		prev.timer.Stop()
		c.deleteMessage(prev.msgID)
	}

	c.posting.Add(1)
	go c.post(p)
	return nil
}

// post renders and sends the challenge. if it can't be posted the member is unmuted, an unsolvable captcha
// must not lock them out. a challenge resolved while it was being posted is deleted right away
func (c *captcha) post(p *pendingCaptcha) {
	defer c.posting.Done()
	c.senders <- struct{}{}
	sent, err := c.send(p.user, p.code)
	<-c.senders

	if err != nil {
		if c.take(p.user.ID, p) != nil {
			c.unmute(p.user)
		}
		log.Printf("[WARN] failed to send captcha to %s: %v", p.user, err)
		return
	}

	c.mu.Lock()
	current := c.pending[p.user.ID] == p
	if current {
		p.msgID = sent.MessageID
	}
	c.mu.Unlock()
	if !current {
		c.deleteMessage(sent.MessageID)
		return
	}
	log.Printf("[INFO] captcha sent to %s, timeout %v", p.user, c.timeout)
}

// HandleCallback processes a keypad press. only the member the captcha was sent to can solve it. the
// number is checked once all its digits are entered, so a wrong digit gives nothing away
func (c *captcha) HandleCallback(query *tbapi.CallbackQuery) error {
	userID, key, err := parseCaptchaData(query.Data)
	if err != nil {
		c.answer(query.ID, captchaExpired)
		return err
	}
	if query.Message == nil || query.Message.Chat.ID != c.chatID {
		c.answer(query.ID, captchaExpired)
		return nil
	}
	if query.From == nil || query.From.ID != userID {
		c.answer(query.ID, "this verification is for another user")
		return nil
	}

	c.mu.Lock()
	p, ok := c.pending[userID]
	if !ok || p.msgID != query.Message.MessageID {
		c.mu.Unlock()
		c.answer(query.ID, captchaExpired)
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
		c.answer(query.ID, strings.TrimSpace(progress))
		return nil
	}
	delete(c.pending, userID)
	p.timer.Stop()
	c.mu.Unlock()

	c.deleteMessage(p.msgID)
	if p.entered != p.code {
		c.answer(query.ID, "wrong answer")
		return c.fail(p.user, "wrong answer", true)
	}
	c.answer(query.ID, "verified")
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
	p := c.take(userID, nil)
	if p == nil {
		return
	}
	c.deleteMessage(p.msgID)
	if err := c.fail(p.user, "left the chat", false); err != nil {
		log.Printf("[WARN] %v", err)
	}
}

// Stop cancels all pending captchas and deletes their messages, waiting for challenges being posted.
// the muted members are released by their restriction expiry
func (c *captcha) Stop() {
	c.mu.Lock()
	msgIDs := make([]int, 0, len(c.pending))
	for id, p := range c.pending {
		p.timer.Stop()
		msgIDs = append(msgIDs, p.msgID)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	c.posting.Wait() // posts find their captcha gone and delete what they sent
	for _, id := range msgIDs {
		c.deleteMessage(id)
	}
}

func (c *captcha) expire(p *pendingCaptcha) {
	if c.take(p.user.ID, p) == nil {
		return // solved, replaced or canceled in the meantime
	}
	c.deleteMessage(p.msgID)
	if err := c.fail(p.user, "timeout", true); err != nil {
		log.Printf("[WARN] %v", err)
	}
}

// take removes the member's pending captcha and returns it. with want set, only that exact entry is taken
func (c *captcha) take(userID int64, want *pendingCaptcha) *pendingCaptcha {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[userID]
	if !ok || (want != nil && p != want) {
		return nil
	}
	delete(c.pending, userID)
	p.timer.Stop()
	return p
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
	return c.ban(user, cooldownFor(f.count), reason)
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

// ban removes the member until the cooldown ends, telegram lifts the ban by itself then. a ban shorter than
// a minute is extended, telegram treats less than 30 seconds as forever
func (c *captcha) ban(user bot.User, d time.Duration, reason string) error {
	d = max(d, time.Minute)
	err := c.request(tbapi.BanChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}, UserID: user.ID},
		UntilDate:        time.Now().Add(d).Unix(),
	})
	if err != nil {
		return fmt.Errorf("failed to remove %s after captcha %s: %w", user, reason, err)
	}
	log.Printf("[INFO] %s removed for %v, captcha %s", user, d.Round(time.Second), reason)
	return nil
}

// unmute lifts the captcha restriction. per the Bot API, passing true for all permissions lifts a
// restriction, the member is then a regular member bound by the chat's default permissions
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
		log.Printf("[WARN] failed to unmute %s, the restriction expires in %v: %v", user, c.timeout+captchaGrace, err)
	}
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

// send posts the animation with a keypad of shuffled digits and a backspace
func (c *captcha) send(user bot.User, code string) (tbapi.Message, error) {
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

	anim := tbapi.NewAnimation(c.chatID, tbapi.FileBytes{Name: "captcha.gif", Bytes: img})
	anim.Caption = c.prompt(user)
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

func (c *captcha) answer(queryID, text string) {
	if _, err := c.tbAPI.Request(tbapi.NewCallback(queryID, text)); err != nil {
		log.Printf("[WARN] failed to answer captcha callback: %v", err)
	}
}

// deleteMessage deletes a captcha message, msgID 0 is a captcha not posted yet
func (c *captcha) deleteMessage(msgID int) {
	if msgID == 0 {
		return
	}
	_, err := c.tbAPI.Request(tbapi.DeleteMessageConfig{BaseChatMessage: tbapi.BaseChatMessage{
		MessageID: msgID, ChatConfig: tbapi.ChatConfig{ChatID: c.chatID}}})
	if err != nil {
		log.Printf("[WARN] failed to delete captcha message %d: %v", msgID, err)
	}
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
