package events

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/routegroup"

	"github.com/umputun/tg-spam/app/config"
	"github.com/umputun/tg-spam/app/openid"
)

// TurnstileConfig switches the captcha from the motion animation to challenge pages: Cloudflare Turnstile when
// SiteKey is set, an OIDC sign-in when OIDC.Issuer is set, or Turnstile followed by the sign-in. the member gets
// a login button opening PublicURL/v/<nonce>, a page served on Listen, and is let in once the page's steps pass.
// the button is a telegram login_url: telegram adds the presser's signed identity, so a tap by anyone else
// is refused. it binds the page to the member's account, not to who solves it: a link the member's side
// opens and relays still works, as with any captcha a human solves. the bot's domain must be set to the
// PublicURL host with @BotFather /setdomain
type TurnstileConfig struct {
	SiteKey   string // public site key of the Turnstile widget
	Secret    string // secret of the widget, for siteverify
	PublicURL string // https base url without a path; its host must be a widget domain and the bot's domain
	Listen    string // address of the page server, meant to be reached only through a tunnel or proxy
	BotToken  string // telegram bot token, only the key derived from it to check login data is kept
	// OIDC asks members to sign in at an OpenID Connect issuer, after Turnstile when SiteKey is set, when its
	// issuer is set. Any account of the issuer passes. The issuer must accept PublicURL + turnstileCallbackPath
	// as a redirect url
	OIDC config.CaptchaOIDCSettings
}

// turnstileCallbackPath is where the issuer returns a member after sign-in, under /v/ like the pages so a
// tunnel or proxy that routes only the pages to the page server covers it too
const turnstileCallbackPath = "/v/oidc/callback"

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// turnstile holds the runtime state of the Turnstile mode
type turnstile struct {
	cfg       TurnstileConfig
	host      string // lower-case host of PublicURL, the hostname siteverify must report
	verifyURL string
	client    *http.Client
	loginAge  time.Duration  // max age of telegram login data, the captcha timeout with a grace
	loginKey  [32]byte       // sha256 of the bot token, the HMAC key of telegram login data
	refused   atomic.Bool    // telegram refused the login button (bot domain not set), use the animation
	idp       *openid.Client // sign-in after turnstile, or instead of it without a site key; nil when not asked for
}

// Pages reports whether the config asks for challenge pages: Turnstile, an OIDC sign-in, or both
func (cfg TurnstileConfig) Pages() bool { return config.CaptchaPages(cfg.SiteKey, cfg.OIDC.Issuer) }

// widget reports whether the pages show the Turnstile widget
func (t *turnstile) widget() bool { return t.cfg.SiteKey != "" }

// WithTurnstile switches the captcha to Turnstile. it must be called before the captcha is used
func (c *captcha) WithTurnstile(cfg TurnstileConfig) error {
	if err := config.ValidateTurnstile(cfg.SiteKey, cfg.Secret, cfg.PublicURL, cfg.Listen, cfg.OIDC.Issuer != ""); err != nil {
		return fmt.Errorf("turnstile: %w", err)
	}
	if cfg.BotToken == "" {
		return errors.New("turnstile needs the bot token to check telegram logins")
	}
	if err := config.ValidateCaptchaOIDC(cfg.OIDC); err != nil {
		return fmt.Errorf("turnstile: %w", err)
	}
	u, _ := url.Parse(cfg.PublicURL)
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	loginKey := sha256.Sum256([]byte(cfg.BotToken))
	cfg.BotToken = "" // only the derived key is kept
	c.turnstile = &turnstile{cfg: cfg, host: strings.ToLower(u.Hostname()), verifyURL: turnstileVerifyURL,
		client: &http.Client{Timeout: 10 * time.Second}, loginAge: c.timeout + captchaGrace, loginKey: loginKey}
	if o := cfg.OIDC; o.Issuer != "" {
		// only the subject is used, so no scope beyond openid is asked for
		c.turnstile.idp = openid.New(openid.Config{Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret,
			RedirectURL: cfg.PublicURL + turnstileCallbackPath})
		c.turnstile.cfg.OIDC.ClientSecret = "" // kept by the client only
	}
	return nil
}

// newNonce returns a random url-safe token naming one challenge page, 128 bits
func newNonce() string { return rand.Text() }

// sendTurnstile posts the caption with a login button opening the challenge page
func (c *captcha) sendTurnstile(chatID int64, nonce, caption, lang string) (tbapi.Message, error) {
	msg := tbapi.NewMessage(chatID, caption)
	msg.ParseMode = tbapi.ModeHTML
	msg.LinkPreviewOptions = tbapi.LinkPreviewOptions{IsDisabled: true}
	msg.ReplyMarkup = tbapi.NewInlineKeyboardMarkup(tbapi.NewInlineKeyboardRow(
		tbapi.NewInlineKeyboardButtonLoginURL(captchaText(lang, txtVerifyButton),
			tbapi.LoginURL{URL: c.turnstile.cfg.PublicURL + "/v/" + nonce})))
	sent, err := c.tbAPI.Send(msg)
	if err != nil {
		return tbapi.Message{}, fmt.Errorf("send turnstile link: %w", err)
	}
	return sent, nil
}

// lookupNonce returns the posted captcha a challenge page belongs to
func (c *captcha) lookupNonce(nonce string) (*pendingCaptcha, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.nonces[nonce]
	return p, ok
}

// solveNonce resolves the captcha of a page whose Turnstile passed. false if it was resolved, replaced or
// expired meanwhile
func (c *captcha) solveNonce(nonce string) bool {
	c.mu.Lock()
	p, ok := c.nonces[nonce]
	test := ok && c.tests[p.user.ID] == p
	c.mu.Unlock()
	if !ok {
		return false
	}
	m := c.pending
	if test {
		m = c.tests
	}
	// take removes only this very entry, so a page can never resolve a newer captcha of the member
	if c.take(m, p.user.ID, p) == nil {
		return false
	}
	deleteMessage(c.tbAPI, p.chatID, p.msgID, "captcha")
	if test {
		c.sendText(p.chatID, captchaText(p.lang, txtTestPassed))
		return true
	}
	c.solved(p)
	return true
}

// telegramLogin checks the login_url data telegram added to the page url and returns the user ID. the data
// is signed with a key derived from the bot token (core.telegram.org/widgets/login#checking-authorization)
// and must be recent
func (t *turnstile) telegramLogin(q url.Values) (int64, error) {
	hash := q.Get("hash")
	if hash == "" {
		return 0, errors.New("no telegram login data")
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		if k != "hash" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+q.Get(k))
	}
	mac := hmac.New(sha256.New, t.loginKey[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	got, err := hex.DecodeString(hash)
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return 0, errors.New("bad telegram login signature")
	}
	authDate, err := strconv.ParseInt(q.Get("auth_date"), 10, 64)
	if err != nil || time.Since(time.Unix(authDate, 0)) > t.loginAge {
		return 0, errors.New("telegram login data expired")
	}
	id, err := strconv.ParseInt(q.Get("id"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad telegram user id: %w", err)
	}
	return id, nil
}

// siteverify checks a Turnstile token with cloudflare. it passes only for a token issued for our host and
// for this page: the widget carries the nonce as cdata, so a token solved on another page can't be used. the
// visitor's address is not passed: it would come from a header anyone reaching the port directly can forge
func (t *turnstile) siteverify(ctx context.Context, token, nonce string) error {
	form := url.Values{"secret": {t.cfg.Secret}, "response": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("make siteverify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("siteverify: %w", err)
	}
	defer resp.Body.Close()
	var res struct {
		Success    bool     `json:"success"`
		Hostname   string   `json:"hostname"`
		CData      string   `json:"cdata"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decode siteverify response, status %d: %w", resp.StatusCode, err)
	}
	if !res.Success {
		return fmt.Errorf("turnstile rejected: %v", res.ErrorCodes)
	}
	if !strings.EqualFold(res.Hostname, t.host) {
		return fmt.Errorf("turnstile token issued for %q, not %q", res.Hostname, t.host)
	}
	if res.CData != nonce {
		return errors.New("turnstile token issued for another challenge page")
	}
	return nil
}

// ListenTurnstile binds the challenge page address, so a bad or taken address fails the start rather than
// leaving members with buttons to a page that is not served
func (c *captcha) ListenTurnstile() (net.Listener, error) {
	ln, err := net.Listen("tcp", c.turnstile.cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("turnstile page listen on %s: %w", c.turnstile.cfg.Listen, err)
	}
	return ln, nil
}

// ServeTurnstile serves the challenge pages on ln until ctx is done. it is public, through a tunnel or proxy,
// and serves nothing but the pages of posted challenges: a page is found only by its random nonce
func (c *captcha) ServeTurnstile(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: c.turnstileRoutes(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("[INFO] captcha pages on %s, public %s, turnstile %v, sign-in %v", ln.Addr(), c.turnstile.cfg.PublicURL,
		c.turnstile.widget(), c.turnstile.idp != nil)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("turnstile page server: %w", err)
	}
	return nil
}

// turnstileRoutes returns the handler of the challenge pages, everything else is 404
func (c *captcha) turnstileRoutes() http.Handler {
	router := routegroup.New(http.NewServeMux())
	router.Use(rest.Recoverer(lgr.Default()), rest.Throttle(100), rest.SizeLimit(16*1024))
	router.HandleFunc("GET /v/{nonce}", c.turnstilePageHandler)
	if c.turnstile.widget() {
		router.HandleFunc("POST /v/{nonce}", c.turnstileVerifyHandler)
	}
	if c.turnstile.idp != nil {
		router.HandleFunc("GET "+turnstileCallbackPath, c.turnstileCallbackHandler)
	}
	return router
}

// pageCaptcha finds the captcha of a page and checks the telegram login of the visitor. on failure it renders
// the error page and returns nil
func (c *captcha) pageCaptcha(w http.ResponseWriter, r *http.Request) (p *pendingCaptcha, lang string) {
	p, ok := c.lookupNonce(r.PathValue("nonce"))
	lang = pageLang(p, r)
	if !ok {
		c.renderPage(w, r, http.StatusNotFound, lang, captchaText(lang, txtPageExpired), false)
		return nil, lang
	}
	userID, err := c.turnstile.telegramLogin(r.URL.Query())
	if err != nil {
		log.Printf("[INFO] captcha page for %s opened without valid telegram login: %v", p.user, err)
		c.renderPage(w, r, http.StatusForbidden, lang, captchaText(lang, txtPageLogin), false)
		return nil, lang
	}
	if userID != p.user.ID {
		c.renderPage(w, r, http.StatusForbidden, lang, captchaText(lang, txtOtherUser), false)
		return nil, lang
	}
	return p, lang
}

// turnstilePageHandler shows the Turnstile widget, or without one sends the member straight to the sign-in
func (c *captcha) turnstilePageHandler(w http.ResponseWriter, r *http.Request) {
	p, lang := c.pageCaptcha(w, r)
	if p == nil {
		return
	}
	if !c.turnstile.widget() {
		if authURL, ok := c.signInURL(w, r, p, r.PathValue("nonce"), lang, false); ok {
			// the location carries the sign-in state, so it gets the page headers, no-store above all
			setPageHeaders(w.Header())
			// the target is the issuer's authorization endpoint; the request adds only a query-encoded state
			http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // not an open redirect, see above
		}
		return
	}
	c.renderPage(w, r, http.StatusOK, lang, captchaText(lang, txtPageHint), true)
}

func (c *captcha) turnstileVerifyHandler(w http.ResponseWriter, r *http.Request) {
	p, lang := c.pageCaptcha(w, r)
	if p == nil {
		return
	}
	if err := c.turnstile.siteverify(r.Context(), r.PostFormValue("cf-turnstile-response"), r.PathValue("nonce")); err != nil {
		log.Printf("[INFO] turnstile failed for %s: %v", p.user, err)
		c.renderPage(w, r, http.StatusForbidden, lang, captchaText(lang, txtPageFailed), true)
		return
	}
	if c.turnstile.idp != nil {
		c.startSignIn(w, r, p, r.PathValue("nonce"), lang, http.StatusOK, txtPageSignIn, false)
		return
	}
	c.finishPage(w, r, r.PathValue("nonce"), lang)
}

// finishPage resolves the captcha of a page and tells the member
func (c *captcha) finishPage(w http.ResponseWriter, r *http.Request, nonce, lang string) {
	if !c.solveNonce(nonce) {
		c.renderPage(w, r, http.StatusNotFound, lang, captchaText(lang, txtPageExpired), false)
		return
	}
	c.renderPage(w, r, http.StatusOK, lang, captchaText(lang, txtPageDone), false)
}

// startSignIn shows a page with the link to the issuer
func (c *captcha) startSignIn(w http.ResponseWriter, r *http.Request, p *pendingCaptcha, nonce, lang string,
	status, text int, fresh bool) {
	if authURL, ok := c.signInURL(w, r, p, nonce, lang, fresh); ok {
		c.renderLinkPage(w, r, status, lang, captchaText(lang, text), authURL, captchaText(lang, txtPageSignInButton))
	}
}

// signInURL returns the issuer's authorization url for a captcha whose page passed the telegram login (and
// Turnstile, when on); on failure it renders the error page. The sign-in recorded for the captcha is kept
// unless fresh is set (after a failed one), so opening the page again, e.g. on a reload, doesn't break a
// sign-in still open in another browser. The state starts with the page nonce, so the callback finds the
// captcha, and carries a random part only this member's browser has seen, so the callback can't be completed
// for a captcha by anyone else
func (c *captcha) signInURL(w http.ResponseWriter, r *http.Request, p *pendingCaptcha, nonce, lang string,
	fresh bool) (string, bool) {
	openid.ExtendWriteDeadline(w)
	provider, err := c.turnstile.idp.Discover(r.Context())
	if err != nil {
		log.Printf("[WARN] captcha sign-in for %s unavailable: %v", p.user, err)
		retry := r.URL.RequestURI() // the page itself, its telegram login data included
		if r.Method != http.MethodGet || r.URL.Path == turnstileCallbackPath {
			retry = "/v/" + nonce // a turnstile post or a callback start over at the page, through telegram
		}
		c.renderLinkPage(w, r, http.StatusBadGateway, lang, captchaText(lang, txtPageSignInFailed), retry,
			captchaText(lang, txtPageSignInButton))
		return "", false
	}
	l := openid.NewLogin()
	l.State = nonce + "." + l.State
	c.mu.Lock()
	current := c.nonces[nonce] == p
	if current {
		if p.login == nil || fresh {
			p.login = &l
		}
		l = *p.login
	}
	c.mu.Unlock()
	if !current {
		c.renderPage(w, r, http.StatusNotFound, lang, captchaText(lang, txtPageExpired), false)
		return "", false
	}
	return provider.AuthCodeURL(l), true
}

// turnstileCallbackHandler finishes the sign-in: the state names the page and must match the sign-in recorded
// for it, the code is exchanged and the id token verified. Any account of the issuer passes. A failed
// sign-in keeps the captcha pending and offers a new one; only the timeout removes the member
func (c *captcha) turnstileCallbackHandler(w http.ResponseWriter, r *http.Request) {
	openid.ExtendWriteDeadline(w)
	q := r.URL.Query()
	state := q.Get("state")
	nonce, _, _ := strings.Cut(state, ".")
	p, ok := c.lookupNonce(nonce)
	lang := pageLang(p, r)
	var l openid.Login
	if ok {
		c.mu.Lock()
		if p.login != nil {
			l = *p.login
		}
		c.mu.Unlock()
	}
	if !ok || l.State == "" || subtle.ConstantTimeCompare([]byte(state), []byte(l.State)) != 1 {
		c.renderPage(w, r, http.StatusNotFound, lang, captchaText(lang, txtPageExpired), false)
		return
	}
	if e := q.Get("error"); e != "" {
		log.Printf("[INFO] captcha sign-in for %s refused by the issuer: %s", p.user, e)
		c.startSignIn(w, r, p, nonce, lang, http.StatusForbidden, txtPageSignInFailed, true)
		return
	}
	claims, err := c.turnstile.idp.Exchange(r.Context(), q.Get("code"), l)
	if err != nil {
		log.Printf("[WARN] captcha sign-in for %s failed: %v", p.user, err)
		c.startSignIn(w, r, p, nonce, lang, http.StatusForbidden, txtPageSignInFailed, true)
		return
	}
	log.Printf("[INFO] captcha sign-in for %s as sub=%s", p.user, claims.Sub)
	c.finishPage(w, r, nonce, lang)
}

// pageLang picks the page language: the member's telegram language when known, else the browser's
func pageLang(p *pendingCaptcha, r *http.Request) string {
	if p != nil && p.lang != "" {
		return p.lang
	}
	lang, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	lang, _, _ = strings.Cut(lang, ";")
	return strings.TrimSpace(lang)
}

// turnstileLang maps a language to one the Turnstile widget supports, "auto" lets the widget pick
func turnstileLang(lang string) string {
	base, _, _ := strings.Cut(strings.ToLower(lang), "-")
	switch base {
	case "zh":
		return "zh-cn"
	case "ru", "en":
		return base
	}
	return "auto"
}

var turnstilePage = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font:16px/1.5 system-ui,-apple-system,sans-serif;background:#f4f5f7;color:#1c1d1f}
main{max-width:22rem;padding:2rem 1.5rem;text-align:center}
.btn{display:inline-block;padding:.6rem 1.6rem;border-radius:.5rem;background:#2481cc;color:#fff;text-decoration:none}
@media (prefers-color-scheme:dark){body{background:#17181a;color:#e8e9eb}}
</style>
{{if .Widget}}<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>{{end}}
</head><body><main>
<p>{{.Text}}</p>
{{if .Link}}<p><a class="btn" href="{{.Link}}">{{.LinkText}}</a></p>{{end}}
{{if .Widget}}<form id="f" method="post">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-cdata="{{.Nonce}}"
 data-language="{{.WidgetLang}}" data-callback="done"></div>
</form>
<script nonce="{{.ScriptNonce}}">function done(){document.getElementById("f").submit()}</script>{{end}}
</main></body></html>`))

// pageCSP is the content security policy of a page without the widget
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"

// setPageHeaders sets the headers every page response carries: never cached, no referrer, the static CSP
// (widget pages extend it)
func setPageHeaders(h http.Header) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", pageCSP)
}

// renderPage writes a challenge page, with the Turnstile widget when widget is set. the form posts to the
// page url itself, query included, so the telegram login data comes along
func (c *captcha) renderPage(w http.ResponseWriter, r *http.Request, status int, lang, text string, widget bool) {
	c.writePage(w, r, status, lang, text, widget, "", "")
}

// renderLinkPage writes a page with a button linking to link
func (c *captcha) renderLinkPage(w http.ResponseWriter, r *http.Request, status int, lang, text, link, linkText string) {
	c.writePage(w, r, status, lang, text, false, link, linkText)
}

func (c *captcha) writePage(w http.ResponseWriter, r *http.Request, status int, lang, text string, widget bool,
	link, linkText string) {
	h := w.Header()
	setPageHeaders(h)
	csp := pageCSP
	scriptNonce := ""
	if widget {
		scriptNonce = newNonce()
		csp += "; script-src https://challenges.cloudflare.com 'nonce-" + scriptNonce + "'; " +
			"frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; form-action 'self'"
	}
	h.Set("Content-Security-Policy", csp)
	w.WriteHeader(status)
	err := turnstilePage.Execute(w, struct {
		Lang, WidgetLang, Title, Text, SiteKey, ScriptNonce, Nonce, Link, LinkText string
		Widget                                                                     bool
	}{Lang: lang, WidgetLang: turnstileLang(lang), Title: captchaText(lang, txtPageTitle), Text: text,
		SiteKey: c.turnstile.cfg.SiteKey, ScriptNonce: scriptNonce, Nonce: r.PathValue("nonce"), Widget: widget,
		Link: link, LinkText: linkText})
	if err != nil {
		log.Printf("[WARN] failed to render turnstile page: %v", err)
	}
}
