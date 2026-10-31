package webapi

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/umputun/tg-spam/app/config"
)

const (
	oidcSessionCookie = "tgspam_session"
	oidcStateCookie   = "tgspam_oidc"
	oidcSessionTTL    = 12 * time.Hour
	oidcStateTTL      = 10 * time.Minute
	oidcLoginPath     = "/auth/login"
	oidcCallbackPath  = "/auth/callback"
	oidcLogoutPath    = "/logout"
)

// oidcAuth guards the web UI with an OpenID Connect login (authorization code with PKCE). Sessions are
// stateless cookies signed with a key generated at startup, so a restart signs everyone out. The allow
// list is checked once, at login.
type oidcAuth struct {
	cfg    config.OIDCSettings
	key    []byte
	client *http.Client

	mu         sync.Mutex // guards the lazily discovered provider fields below
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	endSession string
}

// oidcSession is the payload of the session cookie
type oidcSession struct {
	Sub     string `json:"s"`
	Name    string `json:"n"`
	Expires int64  `json:"e"`
}

// oidcState is the payload of the short-lived cookie carried from the login redirect to the callback
type oidcState struct {
	State    string `json:"st"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Expires  int64  `json:"e"`
}

// oidcClaims are the id token claims the allow list is matched against
type oidcClaims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Username      string   `json:"preferred_username"`
	Roles         []string `json:"roles"`
	Groups        []string `json:"groups"`
}

func newOIDCAuth(cfg config.OIDCSettings) (*oidcAuth, error) {
	if err := config.ValidateOIDC(cfg); err != nil {
		return nil, fmt.Errorf("invalid oidc settings: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("can't generate session key: %w", err)
	}
	return &oidcAuth{cfg: cfg, key: key, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// discover fetches the provider metadata on first use and keeps it, so the web UI starts even while the
// issuer is unreachable and a failed discovery is retried on the next login
func (a *oidcAuth) discover(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.oauth != nil {
		return a.oauth, a.verifier, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, a.client), a.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, nil, fmt.Errorf("can't read oidc provider metadata: %w", err)
	}
	a.endSession = meta.EndSession
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})
	a.oauth = &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimSuffix(a.cfg.URL, "/") + oidcCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	return a.oauth, a.verifier, nil
}

// middleware passes requests with a valid session and the login and logout routes; anything else is sent to the login
// page when it is a page load, or refused with 401 otherwise
func (a *oidcAuth) middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == oidcLoginPath || r.URL.Path == oidcCallbackPath || r.URL.Path == oidcLogoutPath {
			h.ServeHTTP(w, r)
			return
		}
		if _, ok := a.session(r); ok {
			h.ServeHTTP(w, r)
			return
		}
		login := oidcLoginPath
		if r.Method == http.MethodGet {
			login += "?rd=" + url.QueryEscape(r.URL.RequestURI())
		}
		switch {
		case r.Header.Get("HX-Request") == "true":
			w.Header().Set("HX-Redirect", login)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		case r.Method == http.MethodGet:
			http.Redirect(w, r, login, http.StatusFound)
		default:
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

// loginHandler starts the authorization code flow, keeping state, nonce and PKCE verifier in a signed cookie
func (a *oidcAuth) loginHandler(w http.ResponseWriter, r *http.Request) {
	oauth, _, err := a.discover(r.Context())
	if err != nil {
		log.Printf("[WARN] %v", err)
		http.Error(w, "login provider unavailable", http.StatusBadGateway)
		return
	}
	st := oidcState{State: rand.Text(), Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(),
		Return: localPath(r.URL.Query().Get("rd")), Expires: time.Now().Add(oidcStateTTL).Unix()}
	value, err := a.sign(st)
	if err != nil {
		http.Error(w, "can't start login", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, oidcStateCookie, value, oidcCallbackPath, oidcStateTTL)
	authURL := oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// callbackHandler finishes the flow: checks state, exchanges the code, verifies the id token and its nonce,
// matches the account against the allow list and issues the session cookie
func (a *oidcAuth) callbackHandler(w http.ResponseWriter, r *http.Request) {
	var st oidcState
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || !a.verify(c.Value, &st) || time.Now().Unix() > st.Expires {
		http.Error(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	a.setCookie(w, oidcStateCookie, "", oidcCallbackPath, 0)
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "login failed: "+e, http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(st.State)) != 1 {
		http.Error(w, "login state mismatch", http.StatusBadRequest)
		return
	}

	oauth, verifier, err := a.discover(r.Context())
	if err != nil {
		log.Printf("[WARN] %v", err)
		http.Error(w, "login provider unavailable", http.StatusBadGateway)
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.client)
	token, err := oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		log.Printf("[WARN] oidc code exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "login failed: no id token", http.StatusForbidden)
		return
	}
	idToken, err := verifier.Verify(ctx, rawID)
	if err == nil && subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
		err = errors.New("nonce mismatch")
	}
	if err != nil {
		log.Printf("[WARN] oidc id token rejected: %v", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	var claims oidcClaims
	if err = idToken.Claims(&claims); err != nil {
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	if !a.allowed(claims) {
		log.Printf("[WARN] oidc login refused for sub=%s email=%s", claims.Sub, claims.Email)
		http.Error(w, "account not allowed", http.StatusForbidden)
		return
	}

	name := cmp.Or(claims.Username, claims.Email, claims.Sub)
	value, err := a.sign(oidcSession{Sub: claims.Sub, Name: name, Expires: time.Now().Add(oidcSessionTTL).Unix()})
	if err != nil {
		http.Error(w, "can't create session", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, oidcSessionCookie, value, "/", oidcSessionTTL)
	log.Printf("[INFO] oidc login: %s (sub=%s)", name, claims.Sub)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

// logoutHandler drops the session and hands over to the provider's logout page, which ends the provider
// session too; otherwise the next request would sign straight back in
func (a *oidcAuth) logoutHandler(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, oidcSessionCookie, "", "/", 0)
	if _, _, err := a.discover(r.Context()); err == nil && a.endSession != "" {
		http.Redirect(w, r, a.endSession, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// allowed matches the id token claims against the allow list; email entries need a verified email
func (a *oidcAuth) allowed(c oidcClaims) bool {
	for _, entry := range a.cfg.Allow {
		kind, value, _ := strings.Cut(entry, ":")
		switch kind {
		case "role":
			if slices.Contains(c.Roles, value) {
				return true
			}
		case "group":
			if slices.Contains(c.Groups, value) {
				return true
			}
		case "email":
			if c.EmailVerified && strings.EqualFold(c.Email, value) {
				return true
			}
		case "sub":
			if c.Sub == value {
				return true
			}
		}
	}
	return false
}

// session returns the session from a valid, unexpired session cookie
func (a *oidcAuth) session(r *http.Request) (oidcSession, bool) {
	var s oidcSession
	c, err := r.Cookie(oidcSessionCookie)
	if err != nil || !a.verify(c.Value, &s) || time.Now().Unix() > s.Expires {
		return oidcSession{}, false
	}
	return s, true
}

// setCookie sets a cookie living for ttl, or deletes it when ttl is not positive. Secure is unconditional:
// ValidateOIDC only accepts an https public url
func (a *oidcAuth) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	maxAge := -1
	if ttl > 0 {
		maxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// sign encodes v as base64url(json) "." base64url(hmac-sha256)
func (a *oidcAuth) sign(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("can't marshal cookie payload: %w", err)
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(a.mac(p)), nil
}

// verify checks the signature of a value made by sign and decodes its payload into v
func (a *oidcAuth) verify(value string, v any) bool {
	p, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, a.mac(p)) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return false
	}
	return json.Unmarshal(payload, v) == nil
}

func (a *oidcAuth) mac(payload string) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// localPath keeps a post-login return target only when it is a path on this host
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	if u, err := url.Parse(p); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return p
}
