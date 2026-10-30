package events

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/bot"
	"github.com/umputun/tg-spam/app/events/mocks"
)

// fakeSiteverify mocks cloudflare's siteverify, answering with the given hostname for the token "good"
type fakeSiteverify struct {
	srv      *httptest.Server
	hostname string
	cdata    string // the page the token was solved on, reported back as cdata
	mu       sync.Mutex
	forms    []url.Values
}

func newFakeSiteverify(t *testing.T, hostname string) *fakeSiteverify {
	t.Helper()
	f := &fakeSiteverify{hostname: hostname}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		f.mu.Unlock()
		if r.PostForm.Get("response") != "good" {
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
			return
		}
		f.mu.Lock()
		cdata := f.cdata
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"success":true,"hostname":"` + f.hostname + `","cdata":"` + cdata + `"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// solvedOn makes the fake report tokens as solved on the page of nonce
func (f *fakeSiteverify) solvedOn(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cdata = nonce
}

func newTurnstileCaptcha(t *testing.T, timeout time.Duration, hostname string) (*captcha, *mocks.TbAPIMock, *fakeSiteverify) {
	t.Helper()
	api := newCaptchaAPI("member")
	c := newCaptcha(api, 123, timeout, "")
	require.NoError(t, c.WithTurnstile(TurnstileConfig{SiteKey: "site-key", Secret: "secret",
		PublicURL: "https://verify.example.com/", Listen: ":0", BotToken: testBotToken}))
	fake := newFakeSiteverify(t, hostname)
	c.turnstile.verifyURL = fake.srv.URL
	t.Cleanup(c.Stop)
	return c, api, fake
}

func postedNonce(t *testing.T, c *captcha) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Len(t, c.nonces, 1)
	for n := range c.nonces {
		return n
	}
	return ""
}

const testBotToken = "123456:test-token"

// loginQuery builds telegram login_url data for the user, signed like telegram does
func loginQuery(userID int64, authDate time.Time, botToken string) string {
	v := url.Values{"id": {strconv.FormatInt(userID, 10)}, "first_name": {"New"}, "username": {"newbie"},
		"auth_date": {strconv.FormatInt(authDate.Unix(), 10)}}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+v.Get(k))
	}
	secret := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	v.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return v.Encode()
}

// member42 is the signed login of the member the test captchas are for
func member42() string { return loginQuery(42, time.Now(), testBotToken) }

func doPage(c *captcha, method, nonce, token string, hdr map[string]string, query ...string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(url.Values{"cf-turnstile-response": {token}}.Encode())
	} else {
		body = strings.NewReader("")
	}
	target := "/v/" + nonce
	if len(query) > 0 {
		target += "?" + query[0]
	}
	req := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.turnstileRoutes().ServeHTTP(rec, req)
	return rec
}

func TestCaptcha_WithTurnstile(t *testing.T) {
	c := newCaptcha(newCaptchaAPI("member"), 123, time.Minute, "")
	valid := TurnstileConfig{SiteKey: "k", Secret: "s", PublicURL: "https://V.Example.com/", Listen: ":8081",
		BotToken: testBotToken}
	for _, mutate := range []func(*TurnstileConfig){
		func(c *TurnstileConfig) { c.PublicURL = "http://v.example.com" },
		func(c *TurnstileConfig) { c.PublicURL = "v.example.com" },
		func(c *TurnstileConfig) { c.PublicURL = "https://v.example.com/captcha" },
		func(c *TurnstileConfig) { c.PublicURL = "https://v.example.com?a=1" },
		func(c *TurnstileConfig) { c.PublicURL = "https://v.example.com#x" },
		func(c *TurnstileConfig) { c.PublicURL = "https://v.example.com?" },
		func(c *TurnstileConfig) { c.PublicURL = "https://v.example.com#" },
		func(c *TurnstileConfig) { c.PublicURL = "https://:443" },
		func(c *TurnstileConfig) { c.Secret = "" },
		func(c *TurnstileConfig) { c.Listen = "" },
		func(c *TurnstileConfig) { c.BotToken = "" },
	} {
		cfg := valid
		mutate(&cfg)
		require.Error(t, c.WithTurnstile(cfg), "%+v", cfg)
	}
	require.Nil(t, c.turnstile)
	require.NoError(t, c.WithTurnstile(valid))
	assert.Equal(t, "https://V.Example.com", c.turnstile.cfg.PublicURL)
	assert.Equal(t, "v.example.com", c.turnstile.host, "lower-cased, as siteverify reports it")
	assert.Equal(t, time.Minute+captchaGrace, c.turnstile.loginAge)
	assert.Empty(t, c.turnstile.cfg.BotToken, "only the derived login key is kept")
	assert.Equal(t, sha256.Sum256([]byte(testBotToken)), c.turnstile.loginKey)
}

func TestCaptcha_TurnstileJoin(t *testing.T) {
	t.Run("posts a link button with the default prompt", func(t *testing.T) {
		c, api, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42, DisplayName: "New"}, "zh-hans")
		c.running.Wait()
		require.Len(t, api.SendCalls(), 1)
		msg := api.SendCalls()[0].C.(tbapi.MessageConfig)
		assert.Equal(t, int64(123), msg.ChatID)
		assert.Equal(t, `<a href="tg://user?id=42">New</a>，请在 1m 内点击下方按钮完成验证，否则会被移出群组。`, msg.Text,
			"the default prompt in the member's language")
		button := msg.ReplyMarkup.(tbapi.InlineKeyboardMarkup).InlineKeyboard[0][0]
		assert.Equal(t, "点击验证", button.Text, "button in the member's language")
		nonce := postedNonce(t, c)
		assert.Len(t, nonce, 26, "128 random bits, crypto/rand.Text")
		require.NotNil(t, button.LoginURL, "a login button, so the page learns who pressed it")
		assert.Equal(t, "https://verify.example.com/v/"+nonce, button.LoginURL.URL)
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 1, "muted")
	})

	t.Run("passing turnstile lifts the mute", func(t *testing.T) {
		c, api, fake := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		c.failures[42] = captchaFailure{count: 1, last: time.Now().Add(-time.Hour)}
		nonce := postedNonce(t, c)
		fake.solvedOn(nonce)

		page := doPage(c, http.MethodGet, nonce, "", nil, member42())
		assert.Equal(t, http.StatusOK, page.Code)
		assert.Contains(t, page.Body.String(), `data-sitekey="site-key"`)
		assert.Contains(t, page.Body.String(), `data-cdata="`+nonce+`"`, "the token is bound to this page")
		assert.Contains(t, page.Body.String(), "challenges.cloudflare.com/turnstile/v0/api.js")
		csp := page.Header().Get("Content-Security-Policy")
		assert.Contains(t, csp, "default-src 'none'")
		assert.Contains(t, csp, "frame-ancestors 'none'")
		assert.True(t, c.IsPending(42), "a page view resolves nothing")

		done := doPage(c, http.MethodPost, nonce, "good", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, member42())
		assert.Equal(t, http.StatusOK, done.Code)
		assert.Contains(t, done.Body.String(), "Verified")
		assert.False(t, c.IsPending(42))
		assertLifted(t, api, 42)
		assert.Equal(t, []int{77}, deletedIDs(api))
		assert.Zero(t, failuresOf(c, 42))
		require.Len(t, fake.forms, 1)
		assert.Equal(t, "secret", fake.forms[0].Get("secret"))
		assert.Empty(t, fake.forms[0].Get("remoteip"), "a forgeable header is not passed on")

		again := doPage(c, http.MethodPost, nonce, "good", nil, member42())
		assert.Equal(t, http.StatusNotFound, again.Code, "single use")
	})

	t.Run("failed turnstile keeps the captcha pending", func(t *testing.T) {
		c, api, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		rec := doPage(c, http.MethodPost, postedNonce(t, c), "bad", nil, member42())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "try again")
		assert.Contains(t, rec.Body.String(), `data-sitekey="site-key"`, "widget shown again")
		assert.True(t, c.IsPending(42))
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 1, "still muted")
	})

	t.Run("token issued for another host is rejected", func(t *testing.T) {
		c, _, fake := newTurnstileCaptcha(t, time.Minute, "evil.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		fake.solvedOn(postedNonce(t, c))
		rec := doPage(c, http.MethodPost, postedNonce(t, c), "good", nil, member42())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.True(t, c.IsPending(42))
	})

	t.Run("token solved on another page is rejected", func(t *testing.T) {
		c, _, fake := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		fake.solvedOn("another-page")
		rec := doPage(c, http.MethodPost, postedNonce(t, c), "good", nil, member42())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.True(t, c.IsPending(42))
	})

	t.Run("button refused, falls back to the animation", func(t *testing.T) {
		c, api, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.render = stubRender
		api.SendFunc = func(cfg tbapi.Chattable) (tbapi.Message, error) {
			if _, ok := cfg.(tbapi.MessageConfig); ok {
				return tbapi.Message{}, errors.New("Bad Request: BOT_DOMAIN_INVALID")
			}
			return tbapi.Message{MessageID: 78}, nil
		}
		c.Start(bot.User{ID: 42, DisplayName: "New"}, "")
		c.running.Wait()
		require.Len(t, api.SendCalls(), 2)
		anim, ok := api.SendCalls()[1].C.(tbapi.AnimationConfig)
		require.True(t, ok, "the animation is posted instead")
		assert.Equal(t, `<a href="tg://user?id=42">New</a>, choose the number moving in the animation within 1m, `+
			`otherwise you will be removed from the chat. Tap the animation if it does not play.`, anim.Caption,
			"the animation's own prompt, not the button one")
		assert.True(t, c.IsPending(42))
		assert.Regexp(t, `^\d{2}$`, pendingCode(t, c, 42))
		c.mu.Lock()
		assert.Empty(t, c.nonces)
		c.mu.Unlock()
		assert.Len(t, requestsOf[tbapi.RestrictChatMemberConfig](api), 1, "still muted, not let in unverified")
		assert.True(t, c.turnstile.refused.Load(), "domain refusal remembered")

		c.Start(bot.User{ID: 43}, "")
		c.running.Wait()
		require.Len(t, api.SendCalls(), 3, "no second login button attempt")
		_, ok = api.SendCalls()[2].C.(tbapi.AnimationConfig)
		assert.True(t, ok)
	})

	t.Run("other send errors are not remembered", func(t *testing.T) {
		c, api, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.render = stubRender
		api.SendFunc = func(cfg tbapi.Chattable) (tbapi.Message, error) {
			if _, ok := cfg.(tbapi.MessageConfig); ok {
				return tbapi.Message{}, errors.New("timeout")
			}
			return tbapi.Message{MessageID: 78}, nil
		}
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		assert.False(t, c.turnstile.refused.Load())
	})

	t.Run("only the member's own telegram login opens the page", func(t *testing.T) {
		c, _, fake := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		nonce := postedNonce(t, c)
		tampered := strings.Replace(member42(), "id=42", "id=43", 1)
		for name, tc := range map[string]struct {
			query string
			text  string
		}{
			"no login":          {"", "allow the login"},
			"another user":      {loginQuery(43, time.Now(), testBotToken), "this verification is for another user"},
			"stale login":       {loginQuery(42, time.Now().Add(-time.Hour), testBotToken), "allow the login"},
			"other bot's token": {loginQuery(42, time.Now(), "999:other"), "allow the login"},
			"tampered":          {tampered, "allow the login"},
		} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				rec := doPage(c, method, nonce, "good", nil, tc.query)
				assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", name, method)
				assert.Contains(t, rec.Body.String(), tc.text, "%s %s", name, method)
				assert.NotContains(t, rec.Body.String(), "data-sitekey", "%s %s", name, method)
			}
		}
		assert.Empty(t, fake.forms, "no siteverify without the member's login")
		assert.True(t, c.IsPending(42))
	})

	t.Run("unknown nonce and other paths", func(t *testing.T) {
		c, _, fake := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		rec := doPage(c, http.MethodGet, "nope", "", map[string]string{"Accept-Language": "ru-RU,ru;q=0.9"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "Эта проверка устарела")
		assert.NotContains(t, rec.Body.String(), "data-sitekey")
		assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
			rec.Header().Get("Content-Security-Policy"), "no scripts on a page without the widget")
		assert.Equal(t, http.StatusNotFound, doPage(c, http.MethodPost, "nope", "good", nil).Code)
		assert.Empty(t, fake.forms, "no siteverify for an unknown page")

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rec = httptest.NewRecorder()
		c.turnstileRoutes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("timeout bans and forgets the page", func(t *testing.T) {
		c, api, _ := newTurnstileCaptcha(t, 50*time.Millisecond, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		nonce := postedNonce(t, c)
		require.Eventually(t, func() bool { return len(requestsOf[tbapi.BanChatMemberConfig](api)) == 1 },
			time.Second, 10*time.Millisecond)
		assert.Equal(t, http.StatusNotFound, doPage(c, http.MethodPost, nonce, "good", nil, member42()).Code)
		c.mu.Lock()
		assert.Empty(t, c.nonces)
		c.mu.Unlock()
	})

	t.Run("leaving forgets the page", func(t *testing.T) {
		c, _, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		nonce := postedNonce(t, c)
		c.Cancel(42)
		assert.Equal(t, http.StatusNotFound, doPage(c, http.MethodGet, nonce, "", nil, member42()).Code)
	})

	t.Run("rejoining replaces the page", func(t *testing.T) {
		c, _, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		first := postedNonce(t, c)
		c.Start(bot.User{ID: 42}, "")
		c.running.Wait()
		second := postedNonce(t, c)
		assert.NotEqual(t, first, second)
		assert.Equal(t, http.StatusNotFound, doPage(c, http.MethodGet, first, "", nil, member42()).Code)
	})
}

func TestCaptcha_TurnstileTest(t *testing.T) {
	c, api, fake := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
	c.StartTest(bot.User{ID: 42}, "zh")
	c.running.Wait()
	require.Len(t, api.SendCalls(), 1)
	assert.Equal(t, int64(42), api.SendCalls()[0].C.(tbapi.MessageConfig).ChatID)
	nonce := postedNonce(t, c)
	fake.solvedOn(nonce)

	page := doPage(c, http.MethodGet, nonce, "", nil, member42())
	assert.Contains(t, page.Body.String(), "完成下方验证", "page in the member's telegram language")
	assert.Contains(t, page.Body.String(), `data-language="zh-cn"`, "a language turnstile supports")
	assert.Equal(t, http.StatusOK, doPage(c, http.MethodPost, nonce, "good", nil, member42()).Code)

	var texts []string
	for _, call := range api.SendCalls() {
		if m, ok := call.C.(tbapi.MessageConfig); ok && m.ReplyMarkup == nil {
			texts = append(texts, m.Text)
		}
	}
	assert.Equal(t, []string{"验证测试通过，成员这样操作会被放行"}, texts)
	assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api), "nothing done to the tester")
}

func TestCaptcha_ServeTurnstile(t *testing.T) {
	c, _, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
	c.turnstile.cfg.Listen = "127.0.0.1:0"
	ln, err := c.ListenTurnstile()
	require.NoError(t, err)
	_, err = net.Listen("tcp", ln.Addr().String())
	require.Error(t, err, "the address is bound before serving")
	c.turnstile.cfg.Listen = ln.Addr().String()
	_, err = c.ListenTurnstile()
	require.Error(t, err, "a taken address fails at once")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- c.ServeTurnstile(ctx, ln) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestCaptcha_TurnstileTestTimeout(t *testing.T) {
	c, api, _ := newTurnstileCaptcha(t, 50*time.Millisecond, "verify.example.com")
	c.StartTest(bot.User{ID: 42}, "")
	c.running.Wait()
	nonce := postedNonce(t, c)
	require.Eventually(t, func() bool { return len(api.SendCalls()) == 2 }, time.Second, 10*time.Millisecond)
	text := api.SendCalls()[1].C.(tbapi.MessageConfig).Text
	assert.Equal(t, "captcha test timed out after "+compactDuration(50*time.Millisecond)+
		". a member would be removed (test only, nothing happened to you)", text)
	assert.NotContains(t, text, nonce, "the page token is not leaked")
}

func TestTurnstileLang(t *testing.T) {
	for in, want := range map[string]string{"zh-hans": "zh-cn", "zh": "zh-cn", "RU": "ru", "en-US": "en",
		"de": "auto", "": "auto", "*": "auto"} {
		assert.Equal(t, want, turnstileLang(in), in)
	}
}

func TestCaptcha_ServeTurnstileError(t *testing.T) {
	c, _, _ := newTurnstileCaptcha(t, time.Minute, "verify.example.com")
	c.turnstile.cfg.Listen = "127.0.0.1:0"
	ln, err := c.ListenTurnstile()
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	require.Error(t, c.ServeTurnstile(context.Background(), ln), "a dead listener is an error for Do to stop on")
}

func TestCaptcha_TurnstileFallbackTestTimeoutTellsNumber(t *testing.T) {
	c, api, _ := newTurnstileCaptcha(t, 50*time.Millisecond, "verify.example.com")
	c.render = stubRender
	c.turnstile.refused.Store(true)
	c.StartTest(bot.User{ID: 42}, "")
	c.running.Wait()
	code := pendingTestCode(t, c, 42)
	require.Eventually(t, func() bool { return len(api.SendCalls()) == 2 }, time.Second, 10*time.Millisecond)
	assert.Contains(t, api.SendCalls()[1].C.(tbapi.MessageConfig).Text, "the number was "+code,
		"the fallback animation's number is told")
}

func pendingTestCode(t *testing.T, c *captcha, userID int64) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.tests[userID]
	require.True(t, ok)
	return p.code
}
