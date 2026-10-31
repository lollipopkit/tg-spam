package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/gif"
	"slices"
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
	c.Start(user, "")
	c.running.Wait()
}

// captchaKeys returns the posted candidate buttons
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
	assert.Regexp(t, `^\d{2}$`, code)
	assert.NotContains(t, anim.Caption, code)

	markup := anim.ReplyMarkup.(tbapi.InlineKeyboardMarkup)
	require.Len(t, markup.InlineKeyboard, 2, "two rows of three")
	keys := captchaKeys(t, api)
	require.Len(t, keys, captchaChoices)
	labels := make([]string, 0, len(keys))
	for _, k := range keys {
		labels = append(labels, k.Text)
		assert.Regexp(t, `^\d{2}$`, k.Text)
		assert.Equal(t, "C42:"+k.Text, *k.CallbackData)
	}
	assert.Contains(t, labels, code)
	assert.ElementsMatch(t, slices.Compact(slices.Sorted(slices.Values(labels))), labels, "distinct")
	assert.True(t, c.IsPending(42))
	assert.False(t, c.IsPending(43))
}

func TestCaptcha_StartSkipsAndErrors(t *testing.T) {
	t.Run("restricted member keeps the restriction", func(t *testing.T) {
		api := newCaptchaAPI("restricted")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		startPosted(t, c, bot.User{ID: 42})
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})

	t.Run("member restricted by the captcha's own mute is verified again", func(t *testing.T) {
		api := newCaptchaAPI("restricted")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		defer c.Stop()
		require.NoError(t, c.mute(bot.User{ID: 42}, time.Minute))
		startPosted(t, c, bot.User{ID: 42})
		assert.Len(t, api.SendCalls(), 1)
		assert.True(t, c.IsPending(42))
	})

	for _, status := range []string{"administrator", "creator", "left", "kicked"} {
		t.Run(status+" is skipped", func(t *testing.T) {
			api := newCaptchaAPI(status)
			c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
			startPosted(t, c, bot.User{ID: 42})
			assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
			assert.Empty(t, api.SendCalls())
			assert.False(t, c.IsPending(42))
		})
	}

	t.Run("pending from the start, before any API call", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		defer c.Stop()
		c.workers <- struct{}{} // occupy every worker
		c.workers <- struct{}{}
		c.workers <- struct{}{}
		c.workers <- struct{}{}
		c.Start(bot.User{ID: 42}, "")
		assert.True(t, c.IsPending(42))
		assert.Empty(t, api.RequestCalls())
		for range captchaWorkers {
			<-c.workers
		}
		c.running.Wait()
		assert.Len(t, api.SendCalls(), 1)
	})

	t.Run("member status unknown, verified anyway", func(t *testing.T) {
		api := newCaptchaAPI("member")
		inner := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.GetChatMemberConfig); ok {
				return nil, errors.New("api down")
			}
			return inner(cfg)
		}
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		defer c.Stop()
		startPosted(t, c, bot.User{ID: 42})
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 1)
		assert.Len(t, api.SendCalls(), 1)
		assert.True(t, c.IsPending(42))
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
		startPosted(t, c, bot.User{ID: 42})
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
		assert.False(t, c.isMutedByCaptcha(42))
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
		startPosted(t, c, bot.User{ID: 42})
		assertBannedFor(t, api, 42, captchaCooldown)
		assert.Empty(t, requestsOf[tbapi.GetChatMemberConfig](api), "cooldown is checked before the status")
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})

	t.Run("leave and rejoin under the captcha mute hits the cooldown", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		startPosted(t, c, bot.User{ID: 42})
		c.Cancel(42)
		api.RequestFunc = newCaptchaAPI("restricted").RequestFunc
		startPosted(t, c, bot.User{ID: 42})
		assertBannedFor(t, api, 42, captchaCooldown)
		assert.Len(t, api.SendCalls(), 1, "no second challenge")
		assert.False(t, c.IsPending(42))
	})

	t.Run("ban fails, member muted for the cooldown instead", func(t *testing.T) {
		api := newCaptchaAPI("member")
		inner := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.BanChatMemberConfig); ok {
				return nil, errors.New("ban failed")
			}
			return inner(cfg)
		}
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		err := c.fail(bot.User{ID: 42}, "timeout", true)
		require.ErrorContains(t, err, "muted for 5m0s instead")
		mutes := requestsOf[tbapi.RestrictChatMemberConfig](api)
		require.Len(t, mutes, 1)
		assert.Equal(t, &tbapi.ChatPermissions{}, mutes[0].Permissions)
		assert.InDelta(t, time.Now().Add(captchaCooldown).Unix(), mutes[0].UntilDate, 2)
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
		answers := press(t, c, api, 42, 42, 77, code)
		assert.Equal(t, []string{"verified"}, answers)
		assert.False(t, c.IsPending(42))
		assertLifted(t, api, 42)
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
		assert.Zero(t, failuresOf(c, 42))
	})

	t.Run("answers follow the member's telegram language", func(t *testing.T) {
		c, api, code := start(t)
		q := captchaQuery(42, 77, "C42:"+code)
		q.From.LanguageCode = "zh-hans"
		require.NoError(t, c.HandleCallback(q))
		answers := requestsOf[tbapi.CallbackConfig](api)
		require.Len(t, answers, 1)
		assert.Equal(t, "验证通过", answers[0].Text)
	})

	t.Run("wrong number bans for the cooldown, the first press decides", func(t *testing.T) {
		c, api, code := start(t)
		answers := press(t, c, api, 42, 42, 77, wrongCode(code), code)
		assert.Equal(t, []string{"wrong answer", "this verification has expired"}, answers)
		assert.False(t, c.IsPending(42))
		assertBannedFor(t, api, 42, captchaCooldown)
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Equal(t, 1, failuresOf(c, 42))
	})

	t.Run("repeated failure doubles the cooldown", func(t *testing.T) {
		c, api, code := start(t)
		c.failures[42] = captchaFailure{count: 2, last: time.Now().Add(-time.Hour)}
		press(t, c, api, 42, 42, 77, wrongCode(code))
		assertBannedFor(t, api, 42, 4*captchaCooldown)
	})

	t.Run("a press by another user is ignored", func(t *testing.T) {
		c, api, code := start(t)
		answers := press(t, c, api, 99, 42, 77, wrongCode(code))
		assert.Equal(t, []string{"this verification is for another user"}, answers)
		assert.True(t, c.IsPending(42))
		assert.Len(t, api.RequestCalls(), 1, "only the callback answer")
		assert.Equal(t, []string{"verified"}, press(t, c, api, 42, 42, 77, code), "the member still decides")
	})

	t.Run("keys of a replaced captcha message have expired", func(t *testing.T) {
		c, api, code := start(t)
		assert.Equal(t, []string{captchaText("", txtExpired)}, press(t, c, api, 42, 42, 76, code))
		assert.True(t, c.IsPending(42))
	})

	t.Run("callback from another chat is answered and ignored", func(t *testing.T) {
		c, api, code := start(t)
		q := captchaQuery(42, 77, "C42:"+code)
		q.Message.Chat.ID = 555
		require.NoError(t, c.HandleCallback(q))
		assert.True(t, c.IsPending(42))
		answers := requestsOf[tbapi.CallbackConfig](api)
		require.Len(t, answers, 1)
		assert.Equal(t, captchaText("", txtExpired), answers[0].Text)
		assert.Len(t, api.RequestCalls(), 1)
	})

	t.Run("malformed data", func(t *testing.T) {
		c, api, _ := start(t)
		for _, data := range []string{"C42", "Cx:12", "C42:y1", "C42:1", "C42:123", "C42:"} {
			require.Error(t, c.HandleCallback(captchaQuery(42, 77, data)), data)
		}
		assert.True(t, c.IsPending(42))
		assert.Len(t, requestsOf[tbapi.CallbackConfig](api), 6, "every press is answered")
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

func TestCaptcha_TimeoutStartsWhenPosted(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 50*time.Millisecond, testCaptchaMsg)
	defer c.Stop()
	c.render = func(string) ([]byte, error) { time.Sleep(100 * time.Millisecond); return []byte("gif"), nil }
	startPosted(t, c, bot.User{ID: 42})
	assert.True(t, c.IsPending(42), "a slow post does not eat the timeout")
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	require.Eventually(t, func() bool { return len(requestsOf[tbapi.BanChatMemberConfig](api)) == 1 },
		time.Second, 10*time.Millisecond)
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
	startPosted(t, c, bot.User{ID: 42})
	assertBannedFor(t, api, 42, captchaCooldown)
	assert.Len(t, api.SendCalls(), 1)
}

func TestCaptcha_ResolvedWhilePosting(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
	rendering, release := make(chan struct{}), make(chan struct{})
	c.render = func(string) ([]byte, error) { close(rendering); <-release; return []byte("gif"), nil }

	c.Start(bot.User{ID: 42}, "")
	<-rendering
	assert.Equal(t, []string{captchaText("", txtExpired)}, press(t, c, api, 42, 42, 77, "12"), "not posted yet")
	c.Cancel(42)
	assert.Empty(t, deletedIDs(api), "nothing posted to delete yet")
	close(release)
	c.running.Wait()
	assert.Equal(t, []int{77}, deletedIDs(api), "the post finds its captcha gone and deletes the message")
}

func TestCaptcha_Stop(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, 50*time.Millisecond, testCaptchaMsg)
	c.render = stubRender
	startPosted(t, c, bot.User{ID: 42})

	rendering, release := make(chan struct{}), make(chan struct{})
	c.render = func(string) ([]byte, error) { close(rendering); <-release; return []byte("gif"), nil }
	api.SendFunc = func(c tbapi.Chattable) (tbapi.Message, error) { return tbapi.Message{MessageID: 78}, nil }
	c.Start(bot.User{ID: 43}, "")
	<-rendering

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
	mcStyle := captchaStyle()
	data, err := renderMotionCaptcha("472")
	require.NoError(t, err)
	g, err := gif.DecodeAll(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, g.Image, mcStyle.frames)
	bounds := g.Image[0].Bounds()
	bw, bh := bounds.Dx()/mcStyle.block, bounds.Dy()/mcStyle.block
	assert.Equal(t, 2*mcStyle.margin+3*5*mcStyle.scale+2*mcStyle.gap, bw)
	assert.Equal(t, 2*mcStyle.margin+7*mcStyle.scale, bh)

	at := func(f, x, y int) uint8 { return g.Image[f].ColorIndexAt(x*mcStyle.block, y*mcStyle.block) }

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
	assert.InDelta(t, 1.0, down(mcStyle.margin+3*mcStyle.scale+1, mcStyle.margin+14), 0.001, "stroke moves down in every frame")
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
		l.captcha.running.Wait()
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

	t.Run("the language of a member who joined by themselves comes from the sender", func(t *testing.T) {
		l, _ := setup(t, false)
		from := tbapi.User{ID: 42, LanguageCode: "ru"}
		require.NoError(t, l.procJoin(context.Background(), join(from, tbapi.User{ID: 42})))
		l.captcha.mu.Lock()
		assert.Equal(t, "ru", l.captcha.pending[42].lang)
		l.captcha.mu.Unlock()

		l, _ = setup(t, false)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 1, LanguageCode: "ru"},
			tbapi.User{ID: 43, LanguageCode: "zh"})))
		l.captcha.mu.Lock()
		assert.Equal(t, "zh", l.captcha.pending[43].lang, "an inviter's language is not the member's")
		l.captcha.mu.Unlock()
	})

	t.Run("member added by a regular user gets a captcha", func(t *testing.T) {
		l, _ := setup(t, false)
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 1, UserName: "friend"}, tbapi.User{ID: 43})))
		assert.True(t, l.captcha.IsPending(43))
	})

	t.Run("every member is verified on its own", func(t *testing.T) {
		l, api := setup(t, false)
		inner := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if m, ok := cfg.(tbapi.RestrictChatMemberConfig); ok && m.UserID == 42 {
				return nil, errors.New("api down")
			}
			return inner(cfg)
		}
		require.NoError(t, l.procJoin(context.Background(), join(tbapi.User{ID: 1}, tbapi.User{ID: 42}, tbapi.User{ID: 43})))
		l.captcha.running.Wait()
		assert.False(t, l.captcha.IsPending(42), "mute failed")
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
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member, Text: "/report", MessageID: 58,
		ReplyToMessage: &tbapi.Message{MessageID: 10, Chat: tbapi.Chat{ID: 123}, From: &tbapi.User{ID: 7}}}}
	updChan <- tbapi.Update{EditedMessage: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member, Text: "edit", MessageID: 56}}
	l.captcha.running.Wait()
	code := pendingCode(t, l.captcha, 42)
	updChan <- tbapi.Update{CallbackQuery: captchaQuery(99, 77, "C42:"+code)}
	updChan <- tbapi.Update{CallbackQuery: captchaQuery(42, 77, "C42:"+code)}
	// verified member's message goes through the regular checks
	updChan <- tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: 123}, From: &member, Text: "hello", MessageID: 57}}
	close(updChan)
	require.EqualError(t, <-done, "telegram update chan closed")

	assert.Equal(t, []int{55, 56, 58, 56, 77}, deletedIDs(api),
		"join message, the unverified member's message, reply command and edit, the solved captcha")
	answers := make([]string, 0, 4)
	for _, a := range requestsOf[tbapi.CallbackConfig](api) {
		answers = append(answers, a.Text)
	}
	assert.Equal(t, []string{"this verification is for another user", "verified"}, answers)
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
	deleted := deletedIDs(api)
	require.NotEmpty(t, deleted)
	assert.Equal(t, 55, deleted[0], "join message")
	assert.Len(t, deleted[1:], len(api.SendCalls()), "a captcha posted before or after the leave is deleted")
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	// leaving counts as a failure only once the challenge was posted, which may happen before or after the leave
	assert.LessOrEqual(t, failuresOf(l.captcha, 42), len(api.SendCalls()))
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
	assert.Equal(t, captchaText("", txtExpired), answers[0].Text)
}

func TestCaptcha_Test(t *testing.T) {
	sentTexts := func(api *mocks.TbAPIMock) []string {
		var res []string
		for _, c := range api.SendCalls() {
			if m, ok := c.C.(tbapi.MessageConfig); ok {
				res = append(res, m.Text)
			}
		}
		return res
	}
	start := func(t *testing.T, timeout time.Duration) (*captcha, *mocks.TbAPIMock, string) {
		t.Helper()
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, timeout, testCaptchaMsg)
		c.render = stubRender
		t.Cleanup(c.Stop)
		c.StartTest(bot.User{ID: 42, Username: "admin"}, "")
		c.running.Wait()
		c.mu.Lock()
		p, ok := c.tests[42]
		c.mu.Unlock()
		require.True(t, ok)
		return c, api, p.code
	}
	pressDM := func(t *testing.T, c *captcha, keys ...string) {
		t.Helper()
		for _, k := range keys {
			q := captchaQuery(42, 77, "C42:"+k)
			q.Message.Chat.ID = 42
			require.NoError(t, c.HandleCallback(q))
		}
	}

	t.Run("posted in the private chat with the join caption, nothing done to the member", func(t *testing.T) {
		c, api, _ := start(t, time.Minute)
		require.Len(t, api.SendCalls(), 1)
		anim := api.SendCalls()[0].C.(tbapi.AnimationConfig)
		assert.Equal(t, int64(42), anim.ChatID)
		assert.Equal(t, c.prompt(&pendingCaptcha{user: bot.User{ID: 42, Username: "admin"}}), anim.Caption)
		assert.Empty(t, api.RequestCalls(), "no status read, mute or ban")
		assert.False(t, c.IsPending(42), "not a join captcha")
	})

	t.Run("right number passes", func(t *testing.T) {
		c, api, code := start(t, time.Minute)
		pressDM(t, c, code)
		assert.Equal(t, []string{"captcha test passed, a member passing it would be let in"}, sentTexts(api))
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
		assert.Zero(t, failuresOf(c, 42))
	})

	t.Run("wrong number tells the right one, no ban, no failure", func(t *testing.T) {
		c, api, code := start(t, time.Minute)
		wrong := wrongCode(code)
		pressDM(t, c, wrong)
		assert.Equal(t, []string{fmt.Sprintf("captcha test failed: chose %s, the number was %s. a member would be "+
			"removed for 5m, doubling with each further failure (test only, nothing happened to you)", wrong, code)},
			sentTexts(api))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
		assert.Zero(t, failuresOf(c, 42))
	})

	t.Run("timeout tells the number", func(t *testing.T) {
		c, api, code := start(t, 50*time.Millisecond)
		require.Eventually(t, func() bool { return len(sentTexts(api)) == 1 }, time.Second, 10*time.Millisecond)
		assert.Equal(t, []string{"captcha test timed out after " + compactDuration(50*time.Millisecond) +
			", the number was " + code + ". a member would be removed (test only, nothing happened to you)"},
			sentTexts(api))
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
		assert.Zero(t, failuresOf(c, 42))
	})

	t.Run("a test press does not solve a join captcha", func(t *testing.T) {
		c, api, code := start(t, time.Minute)
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		pressDM(t, c, code)
		assert.True(t, c.IsPending(42), "join captcha untouched")
		assert.Len(t, sentTexts(api), 1)
	})

	t.Run("press in a private chat without a test has expired", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		pressDM(t, c, "12")
		answers := requestsOf[tbapi.CallbackConfig](api)
		require.Len(t, answers, 1)
		assert.Equal(t, captchaText("", txtExpired), answers[0].Text)
	})

	t.Run("send fails, reported in the private chat", func(t *testing.T) {
		api := newCaptchaAPI("member")
		api.SendFunc = func(cfg tbapi.Chattable) (tbapi.Message, error) {
			if _, ok := cfg.(tbapi.AnimationConfig); ok {
				return tbapi.Message{}, errors.New("upload failed")
			}
			return tbapi.Message{}, nil
		}
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		c.render = stubRender
		c.StartTest(bot.User{ID: 42}, "")
		c.running.Wait()
		assert.Equal(t, []string{"captcha test failed: send animation: upload failed"}, sentTexts(api))
		c.mu.Lock()
		assert.Empty(t, c.tests)
		c.mu.Unlock()
	})

	t.Run("a replaced test is not rendered, its failure not reported", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
		defer c.Stop()
		renders := 0
		c.render = func(string) ([]byte, error) { renders++; return []byte("gif"), nil }
		for range captchaWorkers {
			c.workers <- struct{}{} // hold the workers so both tests queue
		}
		c.StartTest(bot.User{ID: 42}, "")
		c.StartTest(bot.User{ID: 42}, "")
		for range captchaWorkers {
			<-c.workers
		}
		c.running.Wait()
		assert.Equal(t, 1, renders, "only the newer test is rendered")
		assert.Len(t, api.SendCalls(), 1)

		api.SendFunc = func(cfg tbapi.Chattable) (tbapi.Message, error) {
			if _, ok := cfg.(tbapi.AnimationConfig); ok {
				return tbapi.Message{}, errors.New("upload failed")
			}
			return tbapi.Message{}, nil
		}
		rendering, release := make(chan struct{}), make(chan struct{})
		c.render = func(string) ([]byte, error) { close(rendering); <-release; return []byte("gif"), nil }
		c.StartTest(bot.User{ID: 43}, "")
		<-rendering
		c.mu.Lock()
		delete(c.tests, 43) // resolved while being sent
		c.mu.Unlock()
		close(release)
		c.running.Wait()
		assert.Empty(t, sentTexts(api), "no failure reported for a test no longer current")
	})

	t.Run("stop deletes a pending test", func(t *testing.T) {
		c, api, _ := start(t, time.Minute)
		c.Stop()
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Equal(t, int64(42), requestsOf[tbapi.DeleteMessageConfig](api)[0].ChatID)
	})
}

func TestTelegramListener_procCaptchaTest(t *testing.T) {
	dm := func(from tbapi.User, text string) tbapi.Update {
		return tbapi.Update{Message: &tbapi.Message{Chat: tbapi.Chat{ID: from.ID, Type: "private"}, From: &from, Text: text}}
	}
	setup := func(withCaptcha bool) (*TelegramListener, *mocks.TbAPIMock) {
		api := newCaptchaAPI("member")
		l := &TelegramListener{TbAPI: api, SuperUsers: SuperUsers{"admin"}, BotUsername: "TgSpamBot"}
		l.chatID = 123
		if withCaptcha {
			l.captcha = newCaptcha(api, 123, time.Minute, testCaptchaMsg)
			l.captcha.render = stubRender
		}
		return l, api
	}

	for _, text := range []string{"/captcha", " /CAPTCHA ", "/captcha@tgspambot"} {
		t.Run("superuser "+text, func(t *testing.T) {
			l, api := setup(true)
			defer l.captcha.Stop()
			require.NoError(t, l.procEvents(dm(tbapi.User{ID: 42, UserName: "admin", FirstName: "Ad"}, text)))
			l.captcha.running.Wait()
			require.Len(t, api.SendCalls(), 1)
			assert.Equal(t, int64(42), api.SendCalls()[0].C.(tbapi.AnimationConfig).ChatID)
			assert.Len(t, l.GetDMUsers(), 1, "still recorded as a DM sender")
		})
	}

	t.Run("other text or another bot's command is ignored", func(t *testing.T) {
		l, api := setup(true)
		defer l.captcha.Stop()
		for _, text := range []string{"hi", "/captcha now", "/captcha@otherbot"} {
			require.NoError(t, l.procEvents(dm(tbapi.User{ID: 42, UserName: "admin"}, text)))
		}
		l.captcha.running.Wait()
		assert.Empty(t, api.SendCalls())
	})

	t.Run("an edit into the command is ignored", func(t *testing.T) {
		l, api := setup(true)
		defer l.captcha.Stop()
		upd := dm(tbapi.User{ID: 42, UserName: "admin"}, "/captcha")
		upd.Message.EditDate = 1
		require.NoError(t, l.procEvents(upd))
		l.captcha.running.Wait()
		assert.Empty(t, api.SendCalls())
	})

	t.Run("works when the admin chat is the superuser's private chat", func(t *testing.T) {
		l, api := setup(true)
		defer l.captcha.Stop()
		upd := dm(tbapi.User{ID: 42, UserName: "admin"}, "/captcha")
		l.adminChatID = 42
		require.True(t, l.isAdminChat(upd.Message.Chat.ID, "admin", 42))
		require.True(t, l.procCaptchaTest(upd.Message), "Do calls it before the admin handler")
		l.captcha.running.Wait()
		assert.Len(t, api.SendCalls(), 1)
		assert.False(t, l.procCaptchaTest(&tbapi.Message{Chat: tbapi.Chat{ID: 123, Type: "supergroup"},
			From: &tbapi.User{ID: 42, UserName: "admin"}, Text: "/captcha"}), "not in a group")
	})

	t.Run("non-superuser is ignored", func(t *testing.T) {
		l, api := setup(true)
		defer l.captcha.Stop()
		require.NoError(t, l.procEvents(dm(tbapi.User{ID: 7, UserName: "someone"}, "/captcha")))
		l.captcha.running.Wait()
		assert.Empty(t, api.SendCalls())
	})

	t.Run("captcha disabled is said so", func(t *testing.T) {
		l, api := setup(false)
		require.NoError(t, l.procEvents(dm(tbapi.User{ID: 42, UserName: "admin"}, "/captcha")))
		require.Len(t, api.SendCalls(), 1)
		assert.Equal(t, "captcha is disabled", api.SendCalls()[0].C.(tbapi.MessageConfig).Text)
	})
}

func TestCaptchaCandidates(t *testing.T) {
	for _, code := range []string{"47", "00", "99", "10", "55"} {
		for range 50 {
			got := captchaCandidates(code)
			require.Len(t, got, captchaChoices, code)
			assert.Contains(t, got, code)
			assert.Len(t, slices.Compact(slices.Sorted(slices.Values(got))), captchaChoices, "distinct: %v", got)
			for _, c := range got {
				assert.Regexp(t, `^\d{2}$`, c)
			}
		}
	}
	// decoys are independent of the code: over many draws every other number shows up, not only near misses
	seen := map[string]bool{}
	for range 2000 {
		for _, c := range captchaCandidates("47") {
			seen[c] = true
		}
	}
	assert.Len(t, seen, 100, "decoys cover every 2-digit number")
}

func TestCaptchaText(t *testing.T) {
	assert.Equal(t, "verified", captchaText("", txtVerified))
	assert.Equal(t, "verified", captchaText("de", txtVerified), "missing language falls back to english")
	assert.Equal(t, "验证通过", captchaText("zh", txtVerified))
	assert.Equal(t, "验证通过", captchaText("zh-Hant", txtVerified))
	assert.Equal(t, "验证测试失败：boom", captchaText("zh-hans", txtTestError, "boom"))
	assert.Equal(t, "проверка пройдена", captchaText("ru", txtVerified))
	assert.Equal(t, "тест не удался: boom", captchaText("ru-RU", txtTestError, "boom"))
	for lang, texts := range captchaTexts {
		assert.Len(t, texts, len(captchaTexts["en"]), lang)
		for i, txt := range texts {
			assert.NotEmpty(t, txt, "%s text %d", lang, i)
		}
	}
}

func TestCaptcha_TestChinese(t *testing.T) {
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, time.Minute, testCaptchaMsg)
	c.render = stubRender
	defer c.Stop()
	c.StartTest(bot.User{ID: 42}, "zh-hans")
	c.running.Wait()
	c.mu.Lock()
	code := c.tests[42].code
	c.mu.Unlock()
	q := captchaQuery(42, 77, "C42:"+wrongCode(code))
	q.Message.Chat.ID = 42
	require.NoError(t, c.HandleCallback(q))
	var texts []string
	for _, call := range api.SendCalls() {
		if m, ok := call.C.(tbapi.MessageConfig); ok {
			texts = append(texts, m.Text)
		}
	}
	assert.Equal(t, []string{fmt.Sprintf("验证测试未通过：选择了 %s，正确答案是 %s。成员会被移出 5m，之后每次失败时长翻倍（仅为测试，你不受影响）",
		wrongCode(code), code)}, texts)
	assert.Equal(t, "答案错误", requestsOf[tbapi.CallbackConfig](api)[0].Text)
}

func TestCaptcha_TimeoutMute(t *testing.T) {
	newMuteCaptcha := func(api *mocks.TbAPIMock, timeout time.Duration) *captcha {
		c := newCaptcha(api, 123, timeout, testCaptchaMsg)
		c.render = stubRender
		c.timeoutMute = true
		t.Cleanup(c.Stop)
		return c
	}
	lastRestrict := func(api *mocks.TbAPIMock) tbapi.RestrictChatMemberConfig {
		rs := requestsOf[tbapi.RestrictChatMemberConfig](api)
		require.NotEmpty(t, rs)
		return rs[len(rs)-1]
	}
	timedOut := func(t *testing.T, c *captcha) {
		t.Helper()
		startPosted(t, c, bot.User{ID: 42})
		require.Eventually(t, func() bool { return !c.IsPending(42) && failuresOf(c, 42) == 1 },
			time.Second, 10*time.Millisecond)
	}

	t.Run("timeout mutes for good and keeps the member", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newMuteCaptcha(api, 50*time.Millisecond)
		timedOut(t, c)
		require.Eventually(t, func() bool { return lastRestrict(api).UntilDate == 0 }, time.Second, 10*time.Millisecond)

		r := lastRestrict(api)
		assert.Equal(t, int64(42), r.UserID)
		assert.Equal(t, tbapi.ChatPermissions{}, *r.Permissions, "nothing can be sent")
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api), "not removed from the chat")
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.False(t, c.isMutedByCaptcha(42), "a permanent mute reads as anybody's, no captcha lifts it")
	})

	t.Run("refused permanent mute bans for the cooldown", func(t *testing.T) {
		api := newCaptchaAPI("member")
		base := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if r, ok := cfg.(tbapi.RestrictChatMemberConfig); ok && r.UntilDate == 0 {
				return nil, errors.New("too many requests")
			}
			return base(cfg)
		}
		c := newMuteCaptcha(api, 50*time.Millisecond)
		timedOut(t, c)
		require.Eventually(t, func() bool { return len(requestsOf[tbapi.BanChatMemberConfig](api)) == 1 },
			time.Second, 10*time.Millisecond)
		assertBannedFor(t, api, 42, captchaCooldown)
	})

	t.Run("permanently muted member rejoining keeps the mute and gets no captcha", func(t *testing.T) {
		for _, inCooldown := range []bool{true, false} {
			api := newCaptchaAPI("restricted")
			c := newMuteCaptcha(api, time.Minute)
			if inCooldown {
				require.NoError(t, c.fail(bot.User{ID: 42}, "timeout", false))
			}
			startPosted(t, c, bot.User{ID: 42})
			assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api), "cooldown %v", inCooldown)
			assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
			assert.Empty(t, api.SendCalls(), "no challenge, cooldown %v", inCooldown)
			assert.False(t, c.IsPending(42))
		}
	})

	t.Run("left before answering and rejoined gets a new captcha", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newMuteCaptcha(api, time.Minute)
		require.NoError(t, c.fail(bot.User{ID: 42}, "left the chat", false))
		startPosted(t, c, bot.User{ID: 42})
		assert.Len(t, api.SendCalls(), 1, "never pressed a button, a fresh challenge gives nothing away")
		assert.NotZero(t, lastRestrict(api).UntilDate, "only the join mute")
		assert.True(t, c.IsPending(42))
	})

	t.Run("admins and members who left again are skipped in the cooldown", func(t *testing.T) {
		for _, status := range []string{"administrator", "left"} {
			api := newCaptchaAPI(status)
			c := newMuteCaptcha(api, time.Minute)
			require.NoError(t, c.fail(bot.User{ID: 42}, "left the chat", false))
			startPosted(t, c, bot.User{ID: 42})
			assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api), status)
			assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api), status)
		}
	})

	statusFails := func() *mocks.TbAPIMock {
		api := newCaptchaAPI("member")
		base := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.GetChatMemberConfig); ok {
				return nil, errors.New("too many requests")
			}
			return base(cfg)
		}
		return api
	}
	t.Run("unknown status of a member muted for good before mutes for good again", func(t *testing.T) {
		api := statusFails()
		c := newMuteCaptcha(api, time.Minute)
		require.NoError(t, c.fail(bot.User{ID: 42}, "timeout", false))
		c.muteForeverOrBan(bot.User{ID: 42}, "captcha timeout")
		require.True(t, c.mutedForGood(42))
		startPosted(t, c, bot.User{ID: 42})
		rs := requestsOf[tbapi.RestrictChatMemberConfig](api)
		require.Len(t, rs, 2)
		assert.Zero(t, rs[1].UntilDate, "the join mute must not replace the permanent one")
		assert.Empty(t, api.SendCalls())
		assert.False(t, c.IsPending(42))
	})
	t.Run("unknown status of a member whose failure muted nobody verifies anyway", func(t *testing.T) {
		api := statusFails()
		c := newMuteCaptcha(api, time.Minute)
		require.NoError(t, c.fail(bot.User{ID: 42}, "left the chat", false))
		startPosted(t, c, bot.User{ID: 42})
		assert.Len(t, api.SendCalls(), 1)
	})
	t.Run("leaving during a failing status read mutes nobody", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newMuteCaptcha(api, time.Minute)
		require.NoError(t, c.fail(bot.User{ID: 42}, "timeout", false))
		c.muteForeverOrBan(bot.User{ID: 42}, "captcha timeout")
		base := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.GetChatMemberConfig); ok {
				c.Cancel(42)
				return nil, errors.New("too many requests")
			}
			return base(cfg)
		}
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 1, "only the earlier permanent mute")
	})
	t.Run("unknown status of a new member verifies anyway", func(t *testing.T) {
		api := statusFails()
		c := newMuteCaptcha(api, time.Minute)
		startPosted(t, c, bot.User{ID: 42})
		assert.Len(t, api.SendCalls(), 1)
		assert.True(t, c.IsPending(42))
	})

	t.Run("leaving before the challenge is posted is no failure and mutes nobody", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newMuteCaptcha(api, time.Minute)
		base := api.RequestFunc
		api.RequestFunc = func(cfg tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := cfg.(tbapi.GetChatMemberConfig); ok {
				c.Cancel(42)
			}
			return base(cfg)
		}
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		assert.Zero(t, failuresOf(c, 42), "the member never saw a challenge")
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		assert.Empty(t, api.SendCalls())
	})

	t.Run("a wrong answer still bans", func(t *testing.T) {
		api := newCaptchaAPI("member")
		c := newMuteCaptcha(api, time.Minute)
		startPosted(t, c, bot.User{ID: 42})
		press(t, c, api, 42, 42, 77, wrongCode(pendingCode(t, c, 42)))
		assertBannedFor(t, api, 42, captchaCooldown)
	})
}
