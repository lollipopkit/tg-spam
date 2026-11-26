package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/bot"
	"github.com/umputun/tg-spam/app/events/mocks"
)

// sentNotices returns the captcha notices sent through api
func sentNotices(t *testing.T, api *mocks.TbAPIMock) []tbapi.MessageConfig {
	t.Helper()
	res := make([]tbapi.MessageConfig, 0, len(api.SendCalls()))
	for _, c := range api.SendCalls() {
		msg, ok := c.C.(tbapi.MessageConfig)
		require.True(t, ok)
		res = append(res, msg)
	}
	return res
}

// buttons returns text and callback data of every button of the notice, row by row
func buttons(t *testing.T, markup any) [][2]string {
	t.Helper()
	m, ok := markup.(tbapi.InlineKeyboardMarkup)
	require.True(t, ok)
	res := make([][2]string, 0, len(m.InlineKeyboard))
	for _, row := range m.InlineKeyboard {
		require.Len(t, row, 1)
		res = append(res, [2]string{row[0].Text, *row[0].CallbackData})
	}
	return res
}

func TestCaptchaReports_Flush(t *testing.T) {
	t.Run("one notice for the queued members, a button each", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999}
		r.Add(bot.User{ID: 42, Username: "spam_bot"}, "banned", "for 5m, captcha: wrong_answer")
		r.Add(bot.User{ID: 43, DisplayName: "Shop] 24/7"}, "muted", "for good, captcha: timeout")
		r.flush()

		notices := sentNotices(t, api)
		require.Len(t, notices, 1)
		assert.Equal(t, int64(999), notices[0].ChatID)
		assert.Equal(t, tbapi.ModeMarkdown, notices[0].ParseMode)
		assert.Equal(t, "banned [@spam_bot (42)](tg://user?id=42) for 5m, captcha: wrong\\_answer\n"+
			"muted [Shop 24/7 (43)](tg://user?id=43) for good, captcha: timeout", notices[0].Text)
		assert.Equal(t, [][2]string{{"unban @spam_bot", "U?42"}, {"unban Shop] 24/7", "U?43"}},
			buttons(t, notices[0].ReplyMarkup))

		r.flush()
		assert.Len(t, api.SendCalls(), 1, "nothing queued, nothing sent")
	})
	t.Run("a batch per notice", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999}
		for i := range captchaReportBatch + 5 {
			r.Add(bot.User{ID: int64(i + 1)}, "banned", "for 5m, captcha: timeout")
		}
		r.flush()
		r.flush()
		notices := sentNotices(t, api)
		require.Len(t, notices, 2)
		assert.Len(t, buttons(t, notices[0].ReplyMarkup), captchaReportBatch)
		assert.Equal(t, [2]string{"unban 1", "U?1"}, buttons(t, notices[0].ReplyMarkup)[0])
		assert.Len(t, buttons(t, notices[1].ReplyMarkup), 5)
	})
	t.Run("members past the queue are counted", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999}
		for i := range captchaReportQueue + 3 {
			r.Add(bot.User{ID: int64(i + 1)}, "banned", "for 5m, captcha: timeout")
		}
		r.flush()
		notices := sentNotices(t, api)
		require.Len(t, notices, 1)
		assert.Contains(t, notices[0].Text, "\n3 more banned or muted by the captcha, not listed")
		r.flush()
		assert.NotContains(t, sentNotices(t, api)[1].Text, "more banned")
	})
	t.Run("a long batch is split under telegram's length limit", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999}
		for i := range captchaReportBatch {
			r.Add(bot.User{ID: int64(i + 1), DisplayName: strings.Repeat("ж", 128)}, "muted",
				"for good, captcha: status unknown after a permanent mute")
		}
		for r.flush() {
		}
		notices := sentNotices(t, api)
		require.Len(t, notices, 2)
		total := 0
		for _, n := range notices {
			assert.LessOrEqual(t, len(utf16.Encode([]rune(n.Text))), captchaReportLimit)
			total += len(buttons(t, n.ReplyMarkup))
		}
		assert.Equal(t, captchaReportBatch, total)
	})
	t.Run("a refused notice is sent again, then given up", func(t *testing.T) {
		api := newCaptchaAPI("member")
		fails := 1
		api.SendFunc = func(tbapi.Chattable) (tbapi.Message, error) {
			if fails > 0 {
				fails--
				return tbapi.Message{}, errors.New("too many requests")
			}
			return tbapi.Message{}, nil
		}
		r := &captchaReports{tbAPI: api, chatID: 999}
		r.Add(bot.User{ID: 42}, "banned", "for 5m, captcha: timeout")
		assert.True(t, r.flush(), "queued again")
		assert.False(t, r.flush())
		require.Len(t, api.SendCalls(), 2)
		assert.Equal(t, api.SendCalls()[0].C, api.SendCalls()[1].C)

		fails = captchaReportAttempts
		r.Add(bot.User{ID: 43}, "banned", "for 5m, captcha: timeout")
		for r.flush() {
		}
		assert.Len(t, api.SendCalls(), 2+captchaReportAttempts)
	})
	t.Run("stopping posts what is left", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999, interval: time.Hour}
		for i := range captchaReportBatch + 1 {
			r.Add(bot.User{ID: int64(i + 1)}, "banned", "for 5m, captcha: timeout")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r.Run(ctx)
		assert.Len(t, api.SendCalls(), 2)
	})
	t.Run("run posts on the interval until stopped", func(t *testing.T) {
		api := newCaptchaAPI("member")
		r := &captchaReports{tbAPI: api, chatID: 999, interval: 10 * time.Millisecond}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { r.Run(ctx); close(done) }()
		r.Add(bot.User{ID: 42}, "banned", "for 5m, captcha: timeout")
		require.Eventually(t, func() bool { return len(api.SendCalls()) == 1 }, time.Second, 5*time.Millisecond)
		cancel()
		<-done
	})
}

func TestTelegramListener_ProcCaptchaRelease(t *testing.T) {
	const adminChat, group = int64(999), int64(123)
	notice := func(markup tbapi.InlineKeyboardMarkup) *tbapi.Message {
		return &tbapi.Message{MessageID: 5, Chat: tbapi.Chat{ID: adminChat}, ReplyMarkup: &markup}
	}
	twoMembers := func() tbapi.InlineKeyboardMarkup {
		return tbapi.NewInlineKeyboardMarkup(
			tbapi.NewInlineKeyboardRow(tbapi.NewInlineKeyboardButtonData("unban @spam_bot", "U?42")),
			tbapi.NewInlineKeyboardRow(tbapi.NewInlineKeyboardButtonData("unban 43", "U?43")))
	}
	press := func(l *TelegramListener, msg *tbapi.Message, data string) {
		l.procCaptchaRelease(&tbapi.CallbackQuery{ID: "q", Data: data, Message: msg,
			From: &tbapi.User{ID: 1, UserName: "admin"}})
	}
	lastMarkup := func(t *testing.T, api *mocks.TbAPIMock) [][2]string {
		t.Helper()
		edits := requestsOf[tbapi.EditMessageReplyMarkupConfig](api)
		require.NotEmpty(t, edits)
		e := edits[len(edits)-1]
		assert.Equal(t, adminChat, e.ChatID)
		assert.Equal(t, 5, e.MessageID)
		return buttons(t, *e.ReplyMarkup)
	}
	newListener := func(api *mocks.TbAPIMock) (*TelegramListener, *mocks.BotMock) {
		b := &mocks.BotMock{AddApprovedUserFunc: func(int64, string) error { return nil }}
		return &TelegramListener{TbAPI: api, Bot: b, chatID: group, adminChatID: adminChat}, b
	}

	t.Run("first press asks to confirm, the second lets the member in", func(t *testing.T) {
		api := newCaptchaAPI("kicked")
		l, b := newListener(api)
		msg := notice(twoMembers())
		press(l, msg, "U?42")
		assert.Equal(t, [][2]string{{"confirm unban @spam_bot", "U42"}, {"unban 43", "U?43"}}, lastMarkup(t, api))
		assert.Empty(t, requestsOf[tbapi.UnbanChatMemberConfig](api))
		assert.Empty(t, b.AddApprovedUserCalls())

		msg = notice(*requestsOf[tbapi.EditMessageReplyMarkupConfig](api)[0].ReplyMarkup)
		press(l, msg, "U42")
		unbans := requestsOf[tbapi.UnbanChatMemberConfig](api)
		require.Len(t, unbans, 1)
		assert.Equal(t, int64(42), unbans[0].UserID)
		assert.Equal(t, group, unbans[0].ChatID)
		assert.True(t, unbans[0].OnlyIfBanned)
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
		require.Len(t, b.AddApprovedUserCalls(), 1)
		assert.Equal(t, int64(42), b.AddApprovedUserCalls()[0].ID)
		assert.Equal(t, "@spam_bot", b.AddApprovedUserCalls()[0].Name)
		assert.Equal(t, [][2]string{{"✓ unbanned @spam_bot by @admin", "U.42"}, {"unban 43", "U?43"}}, lastMarkup(t, api))

		edits := len(requestsOf[tbapi.EditMessageReplyMarkupConfig](api))
		press(l, notice(*requestsOf[tbapi.EditMessageReplyMarkupConfig](api)[1].ReplyMarkup), "U.42")
		assert.Len(t, requestsOf[tbapi.EditMessageReplyMarkupConfig](api), edits, "a used button does nothing")
		assert.Len(t, b.AddApprovedUserCalls(), 1)
	})
	t.Run("a name starting like the button keeps it", func(t *testing.T) {
		api := newCaptchaAPI("kicked")
		l, b := newListener(api)
		press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
			tbapi.NewInlineKeyboardButtonData("unban unban me", "U?43")))), "U?43")
		assert.Equal(t, [][2]string{{"confirm unban unban me", "U43"}}, lastMarkup(t, api))
		press(l, notice(*requestsOf[tbapi.EditMessageReplyMarkupConfig](api)[0].ReplyMarkup), "U43")
		require.Len(t, b.AddApprovedUserCalls(), 1)
		assert.Equal(t, "unban me", b.AddApprovedUserCalls()[0].Name)
	})
	t.Run("dry and training modes change nothing", func(t *testing.T) {
		for _, mode := range []string{"dry", "training"} {
			api := newCaptchaAPI("kicked")
			l, b := newListener(api)
			l.Dry, l.TrainingMode = mode == "dry", mode == "training"
			press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
				tbapi.NewInlineKeyboardButtonData("confirm unban 43", "U43")))), "U43")
			assert.Empty(t, requestsOf[tbapi.UnbanChatMemberConfig](api), mode)
			assert.Empty(t, requestsOf[tbapi.EditMessageReplyMarkupConfig](api), mode)
			assert.Empty(t, b.AddApprovedUserCalls(), mode)
			assert.Equal(t, "nothing changed in dry and training modes", requestsOf[tbapi.CallbackConfig](api)[0].Text)
		}
	})
	t.Run("a muted member gets the restriction lifted", func(t *testing.T) {
		api := newCaptchaAPI("restricted")
		l, _ := newListener(api)
		press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
			tbapi.NewInlineKeyboardButtonData("confirm unban 43", "U43")))), "U43")
		assert.Empty(t, requestsOf[tbapi.UnbanChatMemberConfig](api))
		assertLifted(t, api, 43)
	})
	t.Run("unknown status sends both", func(t *testing.T) {
		api := newCaptchaAPI("member")
		base := api.RequestFunc
		api.RequestFunc = func(c tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := c.(tbapi.GetChatMemberConfig); ok {
				return nil, errors.New("too many requests")
			}
			return base(c)
		}
		l, b := newListener(api)
		press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
			tbapi.NewInlineKeyboardButtonData("confirm unban 43", "U43")))), "U43")
		assert.Len(t, requestsOf[tbapi.UnbanChatMemberConfig](api), 1)
		assertLifted(t, api, 43)
		assert.Len(t, b.AddApprovedUserCalls(), 1)
	})
	t.Run("a refused unban approves nobody and keeps the button", func(t *testing.T) {
		api := newCaptchaAPI("kicked")
		base := api.RequestFunc
		api.RequestFunc = func(c tbapi.Chattable) (*tbapi.APIResponse, error) {
			if _, ok := c.(tbapi.UnbanChatMemberConfig); ok {
				return &tbapi.APIResponse{Ok: false, Result: []byte(`"not enough rights"`)}, nil
			}
			return base(c)
		}
		l, b := newListener(api)
		l.captcha = newCaptcha(api, group, time.Minute, testCaptchaMsg)
		l.captcha.render = stubRender
		defer l.captcha.Stop()
		l.captcha.pending[43] = &pendingCaptcha{user: bot.User{ID: 43}, chatID: group, msgID: 77}
		press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
			tbapi.NewInlineKeyboardButtonData("confirm unban 43", "U43")))), "U43")
		assert.True(t, l.captcha.IsPending(43), "the captcha keeps running to its timeout")
		assert.Empty(t, b.AddApprovedUserCalls())
		assert.Empty(t, requestsOf[tbapi.EditMessageReplyMarkupConfig](api))
		answers := requestsOf[tbapi.CallbackConfig](api)
		require.Len(t, answers, 1)
		assert.Equal(t, "failed, see the log", answers[0].Text)
	})
	t.Run("a pending captcha is dropped without a failure", func(t *testing.T) {
		status := "member"
		api := newCaptchaAPI("member")
		api.RequestFunc = func(c tbapi.Chattable) (*tbapi.APIResponse, error) { return memberStatusResponse(c, status), nil }
		l, _ := newListener(api)
		l.captcha = newCaptcha(api, group, time.Minute, testCaptchaMsg)
		l.captcha.render = stubRender
		defer l.captcha.Stop()
		startPosted(t, l.captcha, bot.User{ID: 42})
		require.True(t, l.captcha.IsPending(42))
		require.NoError(t, l.captcha.fail(bot.User{ID: 42}, "wrong answer", false), "an earlier failure")
		status = "restricted" // the join mute

		press(l, notice(tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
			tbapi.NewInlineKeyboardButtonData("confirm unban 42", "U42")))), "U42")
		assert.False(t, l.captcha.IsPending(42))
		assert.Zero(t, failuresOf(l.captcha, 42))
		assert.False(t, l.captcha.isMutedByCaptcha(42))
		assert.Equal(t, []int{77}, deletedIDs(api), "the captcha message is deleted")
		assertLifted(t, api, 42)
	})
	t.Run("presses outside the admin chat are ignored", func(t *testing.T) {
		api := newCaptchaAPI("kicked")
		l, b := newListener(api)
		msg := notice(twoMembers())
		msg.Chat.ID = group
		press(l, msg, "U?42")
		press(l, msg, fmt.Sprintf("U%d", 42))
		assert.Empty(t, requestsOf[tbapi.EditMessageReplyMarkupConfig](api))
		assert.Empty(t, requestsOf[tbapi.UnbanChatMemberConfig](api))
		assert.Empty(t, b.AddApprovedUserCalls())
		assert.Len(t, requestsOf[tbapi.CallbackConfig](api), 2, "every press is answered")
	})
}
