package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/gif"
	"testing"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/bot"
	"github.com/umputun/tg-spam/app/events/mocks"
	"github.com/umputun/tg-spam/lib/spamcheck"
)

const testCaptchaMsg = "{user}, enter the number within {timeout} <now>"

// newCaptchaAPI mocks a chat where every member has the given status and every sent message gets ID 77
func newCaptchaAPI(status string) *mocks.TbAPIMock {
	return &mocks.TbAPIMock{
		SendFunc: func(c tbapi.Chattable) (tbapi.Message, error) { return tbapi.Message{MessageID: 77}, nil },
		RequestFunc: func(c tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := c.(tbapi.GetChatMemberConfig); ok {
				return &tbapi.APIResponse{Ok: true, Result: []byte(`{"status":"` + status + `","user":{"id":1}}`)}, nil
			}
			return &tbapi.APIResponse{Ok: true}, nil
		},
	}
}

func stubRender(string) ([]byte, error) { return []byte("gif"), nil }

// startPosted starts a captcha and waits until the challenge is posted
func startPosted(t *testing.T, c *captcha, user bot.User) {
	t.Helper()
	require.NoError(t, c.Start(user))
	c.posting.Wait()
}

// captchaKeys returns the posted keypad buttons
func captchaKeys(t *testing.T, api *mocks.TbAPIMock) []tbapi.InlineKeyboardButton {
	t.Helper()
	require.NotEmpty(t, api.SendCalls())
	anim := api.SendCalls()[len(api.SendCalls())-1].C.(tbapi.AnimationConfig)
	var buttons []tbapi.InlineKeyboardButton
	for _, row := range anim.ReplyMarkup.(tbapi.InlineKeyboardMarkup).InlineKeyboard {
		buttons = append(buttons, row...)
	}
	return buttons
}

func pendingCode(t *testing.T, c *captcha, userID int64) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[userID]
	require.True(t, ok)
	return p.code
}

func failuresOf(c *captcha, userID int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failures[userID].count
}

// press sends the keys as separate callbacks and returns the answers shown to the presser
func press(t *testing.T, c *captcha, api *mocks.TbAPIMock, fromID, userID int64, msgID int, keys ...string) []string {
	t.Helper()
	before := len(requestsOf[tbapi.CallbackConfig](api))
	for _, k := range keys {
		require.NoError(t, c.HandleCallback(captchaQuery(fromID, msgID, fmt.Sprintf("C%d:%s", userID, k))))
	}
	answers := requestsOf[tbapi.CallbackConfig](api)[before:]
	res := make([]string, 0, len(answers))
	for _, a := range answers {
		res = append(res, a.Text)
	}
	return res
}

func digitsOf(code string) []string {
	res := make([]string, 0, len(code))
	for _, ch := range code {
		res = append(res, string(ch))
	}
	return res
}

// wrongCode returns a code that differs from the given one in every digit
func wrongCode(code string) string {
	res := []byte(code)
	for i := range res {
		res[i] = '0' + (res[i]-'0'+1)%10
	}
	return string(res)
}

func captchaQuery(fromID int64, msgID int, data string) *tbapi.CallbackQuery {
	return &tbapi.CallbackQuery{ID: "q1", From: &tbapi.User{ID: fromID}, Data: data,
		Message: &tbapi.Message{MessageID: msgID, Chat: tbapi.Chat{ID: 123}}}
}

func requestsOf[T any](api *mocks.TbAPIMock) []T {
	var res []T
	for _, c := range api.RequestCalls() {
		if v, ok := c.C.(T); ok {
			res = append(res, v)
		}
	}
	return res
}

func deletedIDs(api *mocks.TbAPIMock) []int {
	dels := requestsOf[tbapi.DeleteMessageConfig](api)
	res := make([]int, 0, len(dels))
	for _, d := range dels {
		res = append(res, d.MessageID)
	}
	return res
}

// assertBannedFor checks the single ban request bans the member until about d from now
func assertBannedFor(t *testing.T, api *mocks.TbAPIMock, userID int64, d time.Duration) {
	t.Helper()
	bans := requestsOf[tbapi.BanChatMemberConfig](api)
	require.Len(t, bans, 1)
	assert.Equal(t, userID, bans[0].UserID)
	assert.Equal(t, int64(123), bans[0].ChatID)
	assert.InDelta(t, time.Now().Add(d).Unix(), bans[0].UntilDate, 2)
	assert.Empty(t, requestsOf[tbapi.UnbanChatMemberConfig](api))
}

// assertLifted checks the last restrict request lifts the restriction
func assertLifted(t *testing.T, api *mocks.TbAPIMock, userID int64) {
	t.Helper()
	restricts := requestsOf[tbapi.RestrictChatMemberConfig](api)
	require.NotEmpty(t, restricts)
	r := restricts[len(restricts)-1]
	assert.Equal(t, userID, r.UserID)
	assert.Zero(t, r.UntilDate)
	assert.True(t, r.UseIndependentChatPermissions)
	assert.Equal(t, &tbapi.ChatPermissions{CanSendMessages: true, CanSendAudios: true, CanSendDocuments: true,
		CanSendPhotos: true, CanSendVideos: true, CanSendVideoNotes: true, CanSendVoiceNotes: true,
		CanSendPolls: true, CanReactToMessages: true, CanSendOtherMessages: true, CanAddWebPagePreviews: true,
		CanEditTag: true, CanChangeInfo: true, CanInviteUsers: true, CanPinMessages: true, CanManageTopics: true},
		r.Permissions)
}

func TestCaptcha_Start(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 2*time.Minute, testCaptchaMsg)
	defer c.Stop()

	before := time.Now()
	startPosted(t, c, bot.User{ID: 42, DisplayName: "Bad <b>Guy</b>"})

	statuses := requestsOf[tbapi.GetChatMemberConfig](api)
	require.Len(t, statuses, 1)
	assert.Equal(t, int64(42), statuses[0].UserID)

	mutes := requestsOf[tbapi.RestrictChatMemberConfig](api)
	require.Len(t, mutes, 1)
	assert.Equal(t, int64(123), mutes[0].ChatID)
	assert.Equal(t, int64(42), mutes[0].UserID)
	assert.Equal(t, &tbapi.ChatPermissions{}, mutes[0].Permissions)
	assert.InDelta(t, before.Add(3*time.Minute).Unix(), mutes[0].UntilDate, 2, "mute outlives the timeout")

	require.Len(t, api.SendCalls(), 1)
	anim := api.SendCalls()[0].C.(tbapi.AnimationConfig)
	assert.Equal(t, int64(123), anim.ChatID)
	assert.Equal(t, tbapi.ModeHTML, anim.ParseMode)
	assert.Equal(t, `<a href="tg://user?id=42">Bad &lt;b&gt;Guy&lt;/b&gt;</a>, enter the number within 2m &lt;now&gt;`,
		anim.Caption)
	file, ok := anim.File.(tbapi.FileBytes)
	require.True(t, ok)
	_, err := gif.DecodeAll(bytes.NewReader(file.Bytes))
	require.NoError(t, err)

	code := pendingCode(t, c, 42)
	assert.Regexp(t, `^\d{3}$`, code)
	assert.NotContains(t, anim.Caption, code)

	keys := captchaKeys(t, api)
	require.Len(t, keys, 11)
	labels := make([]string, 0, len(keys))
	for _, k := range keys {
		labels = append(labels, k.Text)
		key := k.Text
		if key == "⌫" {
			key = captchaBackspace
		}
		assert.Equal(t, "C42:"+key, *k.CallbackData)
	}
	assert.ElementsMatch(t, []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫"}, labels)
	assert.Equal(t, "⌫", keys[10].Text)
	assert.True(t, c.IsPending(42))
	assert.False(t, c.IsPending(43))
}

func TestCaptcha_StartSkipsAndErrors(t *testing.T) {
	t.Run("restricted member keeps the restriction", func(t *testing.T) {
		api := newCaptchaAPI("restricted")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		require.NoError(t, c.Start(bot.User{ID: 42}))
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})

	t.Run("member status unknown, nothing done", func(t *testing.T) {
		api := newCaptchaAPI("member")
		api.RequestFunc = func(c tbapi.Chattable) (*tbapi.APIResponse, error) { return nil, errors.New("api down") }
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		require.ErrorContains(t, c.Start(bot.User{ID: 42}), "api down")
		assert.Len(t, api.RequestCalls(), 1)
		assert.False(t, c.IsPending(42))
	})

	t.Run("mute fails, nothing sent", func(t *testing.T) {
		api := newCaptchaAPI("member")
		inner := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.RestrictChatMemberConfig); ok {
				return &tbapi.APIResponse{Ok: false, Result: []byte(`"not enough rights"`)}, nil
			}
			return inner(cfg)
		}
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		require.ErrorContains(t, c.Start(bot.User{ID: 42}), "not enough rights")
		c.posting.Wait()
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})

	t.Run("render fails, member unmuted", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = func(string) ([]byte, error) { return nil, errors.New("render failed") }
		startPosted(t, c, bot.User{ID: 42})
		assert.Empty(t, api.SendCalls())
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 2)
		assertLifted(t, api, 42)
		assert.False(t, c.IsPending(42))
	})

	t.Run("send fails, member unmuted", func(t *testing.T) {
		api := newCaptchaAPI("member")
		api.SendFunc = func(c tbapi.Chattable) (tbapi.Message, error) { return tbapi.Message{}, errors.New("send failed") }
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		startPosted(t, c, bot.User{ID: 42})
		assertLifted(t, api, 42)
		assert.False(t, c.IsPending(42))
	})

	t.Run("member in cooldown is banned for the rest of it", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		require.NoError(t, c.fail(bot.User{ID: 42}, "left the chat", false))
		require.NoError(t, c.Start(bot.User{ID: 42}))
		c.posting.Wait()
		assertBannedFor(t, api, 42, captchaCooldown)
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})
}

func TestCaptcha_HandleCallback(t *testing.T) {
	start := func(t *testing.T) (*captcha, *mocks.TbAPIMock, string) {
		t.Helper()
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		t.Cleanup(c.Stop)
		startPosted(t, c, bot.User{ID: 42, Username: "newbie"})
		api.ResetRequestCalls()
		return c, api, pendingCode(t, c, 42)
	}

	t.Run("right number lifts the mute and clears failures", func(t *testing.T) {
		c, api, code := start(t)
		c.failures[42] = captchaFailure{count: 2, last: time.Now().Add(-time.Hour)}
		answers := press(t, c, api, 42, 42, 77, digitsOf(code)...)
		assert.Equal(t, []string{"● ○ ○", "● ● ○", "verified"}, answers)
		assert.False(t, c.IsPending(42))
		assertLifted(t, api, 42)
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
		assert.Zero(t, failuresOf(c, 42))
	})

	t.Run("backspace corrects a digit", func(t *testing.T) {
		c, api, code := start(t)
		keys := append([]string{wrongCode(code)[:1], captchaBackspace, captchaBackspace}, digitsOf(code)...)
		answers := press(t, c, api, 42, 42, 77, keys...)
		assert.Equal(t, []string{"● ○ ○", "○ ○ ○", "○ ○ ○", "● ○ ○", "● ● ○", "verified"}, answers)
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	})

	t.Run("wrong number bans for the cooldown after the last digit", func(t *testing.T) {
		c, api, code := start(t)
		answers := press(t, c, api, 42, 42, 77, digitsOf(wrongCode(code))...)
		assert.Equal(t, []string{"● ○ ○", "● ● ○", "wrong answer"}, answers)
		assert.False(t, c.IsPending(42))
		assertBannedFor(t, api, 42, captchaCooldown)
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Equal(t, 1, failuresOf(c, 42))
	})

	t.Run("repeated failure doubles the cooldown", func(t *testing.T) {
		c, api, code := start(t)
		c.failures[42] = captchaFailure{count: 2, last: time.Now().Add(-time.Hour)}
		press(t, c, api, 42, 42, 77, digitsOf(wrongCode(code))...)
		assertBannedFor(t, api, 42, 4*captchaCooldown)
	})

	t.Run("keys pressed by another user are ignored", func(t *testing.T) {
		c, api, code := start(t)
		answers := press(t, c, api, 99, 42, 77, digitsOf(code)...)
		assert.Equal(t, []string{"this verification is for another user", "this verification is for another user",
			"this verification is for another user"}, answers)
		assert.True(t, c.IsPending(42))
		assert.Len(t, api.RequestCalls(), 3, "only the callback answers")
		assert.Equal(t, []string{"● ○ ○"}, press(t, c, api, 42, 42, 77, code[:1]), "no digits entered by others")
	})

	t.Run("keys of a replaced captcha message have expired", func(t *testing.T) {
		c, api, code := start(t)
		assert.Equal(t, []string{captchaExpired}, press(t, c, api, 42, 42, 76, code[:1]))
		assert.True(t, c.IsPending(42))
	})

	t.Run("callback from another chat is answered and ignored", func(t *testing.T) {
		c, api, code := start(t)
		q := captchaQuery(42, 77, "C42:"+code[:1])
		q.Message.Chat.ID = 555
		require.NoError(t, c.HandleCallback(q))
		assert.True(t, c.IsPending(42))
		answers := requestsOf[tbapi.CallbackConfig](api)
		require.Len(t, answers, 1)
		assert.Equal(t, captchaExpired, answers[0].Text)
		assert.Len(t, api.RequestCalls(), 1)
	})

	t.Run("malformed data", func(t *testing.T) {
		c, api, _ := start(t)
		for _, data := range []string{"C42", "Cx:1", "C42:y", "C42:12", "C42:"} {
			require.Error(t, c.HandleCallback(captchaQuery(42, 77, data)), data)
		}
		assert.True(t, c.IsPending(42))
		assert.Len(t, requestsOf[tbapi.CallbackConfig](api), 5, "every press is answered")
	})
}

func TestCaptcha_Timeout(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 50*time.Millisecond, testCaptchaMsg)
	c.render = stubRender
	defer c.Stop()
	startPosted(t, c, bot.User{ID: 42})

	require.Eventually(t, func() bool { return len(requestsOf[tbapi.BanChatMemberConfig](api)) == 1 },
		time.Second, 10*time.Millisecond)
	assert.False(t, c.IsPending(42))
	assertBannedFor(t, api, 42, captchaCooldown)
	assert.Equal(t, []int{77}, deletedIDs(api))
	assert.Equal(t, 1, failuresOf(c, 42))
}

func TestCaptcha_Restart(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 100*time.Millisecond, testCaptchaMsg)
	c.render = stubRender
	defer c.Stop()
	startPosted(t, c, bot.User{ID: 42})
	api.SendFunc = func(c tbapi.Chattable) (tbapi.Message, error) { return tbapi.Message{MessageID: 78}, nil }
	startPosted(t, c, bot.User{ID: 42})

	assert.Equal(t, []int{77}, deletedIDs(api), "previous captcha message deleted")

	require.Eventually(t, func() bool { return len(requestsOf[tbapi.BanChatMemberConfig](api)) > 0 },
		time.Second, 10*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	assert.Len(t, requestsOf[tbapi.BanChatMemberConfig](api), 1, "the replaced captcha does not time out on its own")
}

func TestCaptcha_Cancel(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 50*time.Millisecond, testCaptchaMsg)
	c.render = stubRender
	defer c.Stop()
	startPosted(t, c, bot.User{ID: 42})

	c.Cancel(42)
	c.Cancel(1) // not pending, no-op
	assert.False(t, c.IsPending(42))
	assert.Equal(t, []int{77}, deletedIDs(api))
	assert.Equal(t, 1, failuresOf(c, 42), "leaving counts as a failure")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api), "no ban for a member who left, no timeout")

	// rejoining right away runs into the cooldown
	require.NoError(t, c.Start(bot.User{ID: 42}))
	assertBannedFor(t, api, 42, captchaCooldown)
	assert.Len(t, api.SendCalls(), 1)
}

func TestCaptcha_ResolvedWhilePosting(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
	release := make(chan struct{})
	c.render = func(string) ([]byte, error) { <-release; return []byte("gif"), nil }

	require.NoError(t, c.Start(bot.User{ID: 42}))
	assert.Equal(t, []string{captchaExpired}, press(t, c, api, 42, 42, 77, "1"), "not posted yet")
	c.Cancel(42)
	assert.Empty(t, deletedIDs(api), "nothing posted to delete yet")
	close(release)
	c.posting.Wait()
	assert.Equal(t, []int{77}, deletedIDs(api), "the post finds its captcha gone and deletes the message")
}

func TestCaptcha_Stop(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 50*time.Millisecond, testCaptchaMsg)
	c.render = stubRender
	startPosted(t, c, bot.User{ID: 42})

	release := make(chan struct{})
	c.render = func(string) ([]byte, error) { <-release; return []byte("gif"), nil }
	api.SendFunc = func(c tbapi.Chattable) (tbapi.Message, error) { return tbapi.Message{MessageID: 78}, nil }
	require.NoError(t, c.Start(bot.User{ID: 43}))

	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	require.Eventually(t, func() bool { return !c.IsPending(42) && !c.IsPending(43) }, time.Second, time.Millisecond)
	close(release)
	<-stopped

	assert.ElementsMatch(t, []int{77, 78}, deletedIDs(api), "posted and in-flight captchas deleted")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api), "no timeouts after stop")
}

func TestCooldownFor(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 5 * time.Minute},
		{2, 10 * time.Minute},
		{3, 20 * time.Minute},
		{9, 1280 * time.Minute},
		{10, 24 * time.Hour},
		{100, 24 * time.Hour},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, cooldownFor(tt.failures), "failures %d", tt.failures)
	}
}

func TestCaptcha_FailuresExpire(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
	c.failures[1] = captchaFailure{count: 5, last: time.Now().Add(-25 * time.Hour)}
	c.failures[2] = captchaFailure{count: 1, last: time.Now()}
	require.NoError(t, c.fail(bot.User{ID: 42}, "timeout", false))
	assert.Zero(t, failuresOf(c, 1), "stale failure forgotten")
	assert.Equal(t, 1, failuresOf(c, 2))
	assert.Zero(t, c.cooldownLeft(1))
	assert.InDelta(t, captchaCooldown.Seconds(), c.cooldownLeft(2).Seconds(), 2)
}

func TestRenderMotionCaptcha(t *testing.T) {
	data, err := renderMotionCaptcha("472")
	require.NoError(t, err)
	g, err := gif.DecodeAll(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, g.Image, mcFrames)
	bounds := g.Image[0].Bounds()
	bw, bh := bounds.Dx()/mcBlock, bounds.Dy()/mcBlock
	assert.Equal(t, 2*mcMargin+3*5*mcGlyphScale+2*mcGap, bw)
	assert.Equal(t, 2*mcMargin+7*mcGlyphScale, bh)

	at := func(f, x, y int) uint8 { return g.Image[f].ColorIndexAt(x*mcBlock, y*mcBlock) }

	// every frame is noise: about half of the blocks are white, in the digit area and outside it alike
	for f := range g.Image {
		white := 0
		for y := range bh {
			for x := range bw {
				white += int(at(f, x, y))
			}
		}
		assert.InDelta(t, 0.5, float64(white)/float64(bw*bh), 0.05, "frame %d", f)
	}

	// the digits show up in motion only: a block that repeats the block above it from the previous frame
	// moves down. that holds in every frame inside a stroke, and about half of the time elsewhere
	down := func(x, y int) float64 {
		n := 0
		for f := 0; f+1 < len(g.Image); f++ {
			if at(f+1, x, y) == at(f, x, y-1) {
				n++
			}
		}
		return float64(n) / float64(len(g.Image)-1)
	}
	// the 4th font column of "4" is ink in every row, so its middle is inside the stroke whatever the
	// jitter; the corner is always background
	assert.InDelta(t, 1.0, down(mcMargin+3*mcGlyphScale+1, mcMargin+14), 0.001, "stroke moves down in every frame")
	assert.Less(t, down(1, 2), 0.8, "background does not move down")

	_, err = renderMotionCaptcha("4a2")
	require.Error(t, err)
}

func TestCompactDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{2 * time.Minute, "2m"},
		{90 * time.Second, "1m30s"},
		{30 * time.Second, "30s"},
		{time.Hour, "1h"},
		{time.Hour + 30*time.Minute, "1h30m"},
		{24 * time.Hour, "24h"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, compactDuration(tt.in), tt.in.String())
	}
}

func TestProcJoin_Captcha(t *testing.T) {
	setup := func(t *testing.T, approved bool) (*TelegramListener, *mocks.TbAPIMock) {
		t.Helper()
		api := newCaptchaAPI("member")
		b := &mocks.BotMock{
			OnJoinFunc:         func(user bot.User) bot.Response { return bot.Response{} },
			IsApprovedUserFunc: func(userID int64) bool { return approved },
		}
		l := &TelegramListener{TbAPI: api, Bot: b, SuperUsers: SuperUsers{"admin"}, BotUsername: "TgSpamBot"}
		l.chatID = 123
		l.captcha = newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		l.captcha.render = stubRender
		t.Cleanup(l.captcha.Stop)
		return l, api
	}
	join := func(from tbapi.User, members ...tbapi.User) *tbapi.Message {
		return &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &from, NewChatMembers: members, MessageID: 55}
	}

	t.Run("member who passed the join check gets a captcha", func(t *testing.T) {
		l, api := setup(t, false)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 42}, tbapi.User{ID: 42, FirstName: "New"})))
		l.captcha.posting.Wait()
		assert.True(t, l.captcha.IsPending(42))
		assert.Len(t, api.SendCalls(), 1)
	})

	t.Run("approved users, bots and members added by a superuser are trusted", func(t *testing.T) {
		l, api := setup(t, true)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 42}, tbapi.User{ID: 42})))
		assert.False(t, l.captcha.IsPending(42))
		assert.Empty(t, api.RequestCalls())

		l, api = setup(t, false)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 1, UserName: "admin"},
			tbapi.User{ID: 43}, tbapi.User{ID: 44, IsBot: true})))
		assert.False(t, l.captcha.IsPending(43))
		assert.False(t, l.captcha.IsPending(44))
		assert.Empty(t, api.RequestCalls())
	})

	t.Run("member added by a regular user gets a captcha", func(t *testing.T) {
		l, _ := setup(t, false)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 1, UserName: "friend"}, tbapi.User{ID: 43})))
		assert.True(t, l.captcha.IsPending(43))
	})

	t.Run("captcha error is returned and does not stop the next member", func(t *testing.T) {
		l, api := setup(t, false)
		inner := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if m, ok := cfg.(tbapi.GetChatMemberConfig); ok && m.UserID == 42 {
				return nil, errors.New("api down")
			}
			return inner(cfg)
		}
		err := l.procJoin(context.Background(), join(tbapi.User{ID: 1}, tbapi.User{ID: 42}, tbapi.User{ID: 43}))
		require.ErrorContains(t, err, "api down")
		assert.False(t, l.captcha.IsPending(42))
		assert.True(t, l.captcha.IsPending(43))
	})

	t.Run("flagged member is banned without a captcha", func(t *testing.T) {
		l, api := setup(t, false)
		l.Bot.(*mocks.BotMock).OnJoinFunc = func(user bot.User) bot.Response {
			return bot.Response{BanInterval: bot.PermanentBanDuration, User: user,
				CheckResults: []spamcheck.Response{{Name: "lua-names", Spam: true}}}
		}
		l.Locator = &mocks.LocatorMock{AddSpamFunc: func(context.Context, int64, []spamcheck.Response) error { return nil }}
		l.SpamLogger = &mocks.SpamLoggerMock{SaveFunc: func(*bot.Message, *bot.Response) {}}
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 42}, tbapi.User{ID: 42})))
		assert.False(t, l.captcha.IsPending(42))
		assert.Len(t, requestsOf[tbapi.BanChatMemberConfig](api), 1)
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, requestsOf[tbapi.GetChatMemberConfig](api))
	})
}

func TestTelegramListener_DoCaptcha(t *testing.T) {
	api := newCaptchaAPI("member")
	api.GetChatAdministratorsFunc = func(tbapi.ChatAdministratorsConfig) ([]tbapi.ChatMember, error) { return nil, nil }
	api.GetChatFunc = func(tbapi.ChatInfoConfig) (tbapi.ChatFullInfo, error) { return tbapi.ChatFullInfo{}, nil }
	b := &mocks.BotMock{
		OnJoinFunc:         func(user bot.User) bot.Response { return bot.Response{} },
		IsApprovedUserFunc: func(userID int64) bool { return false },
		OnMessageFunc:      func(msg bot.Message, checkOnly bool) bot.Response { return bot.Response{} },
	}
	locator := &mocks.LocatorMock{
		AddMessageFunc: func(context.Context, string, int64, int64, string, int) error { return nil },
	}
	l := TelegramListener{TbAPI: api, Bot: b, Group: "123", Locator: locator, DeleteJoinMessages: true,
		CaptchaEnabled: true, CaptchaTimeout: time.Minute, CaptchaMessage: testCaptchaMsg}

	updChan := make(chan tbapi.Update)
	api.GetUpdatesChanFunc = func(tbapi.UpdateConfig) tbapi.UpdatesChannel { return updChan }
	done := make(chan error)
	go func() { done <- l.Do(context.Background()) }()

	member := tbapi.User{ID: 42, FirstName: "New"}
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member,
		NewChatMembers: []tbapi.User{member}, MessageID: 55}}
	// slipped through before the mute
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member, Text: "buy now", MessageID: 56}}
	l.captcha.posting.Wait()
	code := pendingCode(t, l.captcha, 42)
	updChan <- tbapi.Update{CallbackQuery: captchaQuery(99, 77, "C42:"+code[:1])}
	for _, d := range digitsOf(code) {
		updChan <- tbapi.Update{CallbackQuery: captchaQuery(42, 77, "C42:"+d)}
	}
	// verified member's message goes through the regular checks
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member, Text: "hello", MessageID: 57}}
	close(updChan)
	require.EqualError(t, <-done, "telegram update chan closed")

	assert.Equal(t, []int{55, 56, 77}, deletedIDs(api), "join message, the unverified member's message, the solved captcha")
	answers := make([]string, 0, 4)
	for _, a := range requestsOf[tbapi.CallbackConfig](api) {
		answers = append(answers, a.Text)
	}
	assert.Equal(t, []string{"this verification is for another user", "● ○ ○", "● ● ○", "verified"}, answers)
	require.Len(t, b.OnMessageCalls(), 1, "only the verified member's message is checked")
	assert.Equal(t, "hello", b.OnMessageCalls()[0].Msg.Text)
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
}

func TestTelegramListener_DoCaptchaCanceledOnLeave(t *testing.T) {
	api := newCaptchaAPI("member")
	api.GetChatAdministratorsFunc = func(tbapi.ChatAdministratorsConfig) ([]tbapi.ChatMember, error) { return nil, nil }
	api.GetChatFunc = func(tbapi.ChatInfoConfig) (tbapi.ChatFullInfo, error) { return tbapi.ChatFullInfo{}, nil }
	b := &mocks.BotMock{
		OnJoinFunc:         func(user bot.User) bot.Response { return bot.Response{} },
		IsApprovedUserFunc: func(userID int64) bool { return false },
	}
	l := TelegramListener{TbAPI: api, Bot: b, Group: "123", DeleteJoinMessages: true,
		CaptchaEnabled: true, CaptchaTimeout: time.Minute, CaptchaMessage: testCaptchaMsg}
	member := tbapi.User{ID: 42}
	updChan := make(chan tbapi.Update, 2)
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member,
		NewChatMembers: []tbapi.User{member}, MessageID: 55}}
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member,
		LeftChatMember: &member, MessageID: 60}}
	close(updChan)
	api.GetUpdatesChanFunc = func(tbapi.UpdateConfig) tbapi.UpdatesChannel { return updChan }

	require.EqualError(t, l.Do(context.Background()), "telegram update chan closed")
	assert.False(t, l.captcha.IsPending(42))
	assert.ElementsMatch(t, []int{55, 77}, deletedIDs(api), "join message and the captcha message, posted or in flight")
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	assert.Equal(t, 1, failuresOf(l.captcha, 42))
}

func TestTelegramListener_DoCaptchaDisabledInDryMode(t *testing.T) {
	api := newCaptchaAPI("member")
	api.GetChatAdministratorsFunc = func(tbapi.ChatAdministratorsConfig) ([]tbapi.ChatMember, error) { return nil, nil }
	api.GetChatFunc = func(tbapi.ChatInfoConfig) (tbapi.ChatFullInfo, error) { return tbapi.ChatFullInfo{}, nil }
	updChan := make(chan tbapi.Update, 1)
	updChan <- tbapi.Update{CallbackQuery: captchaQuery(42, 77, "C42:1")}
	close(updChan)
	api.GetUpdatesChanFunc = func(tbapi.UpdateConfig) tbapi.UpdatesChannel { return updChan }
	l := TelegramListener{TbAPI: api, Bot: &mocks.BotMock{}, Group: "123", Dry: true,
		CaptchaEnabled: true, CaptchaTimeout: time.Minute, CaptchaMessage: testCaptchaMsg}
	require.EqualError(t, l.Do(context.Background()), "telegram update chan closed")
	assert.Nil(t, l.captcha)
	answers := requestsOf[tbapi.CallbackConfig](api)
	require.Len(t, answers, 1, "a press on a left-over captcha is still answered")
	assert.Equal(t, captchaExpired, answers[0].Text)
}
