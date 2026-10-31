package webapi

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"lukechampine.com/blake3"

	"github.com/umputun/tg-spam/app/config"
)

const (
	oidcSessionCookie = "tgspam_session"
	oidcStatePrefix   = "tgspam_oidc_" // followed by the state value, one cookie per login in flight
	oidcSessionTTL    = 12 * time.Hour
	oidcStateTTL      = 10 * time.Minute
	oidcStateMax      = 3 // login cookies kept per browser, older ones are dropped by the next login
	oidcStatePath     = "/auth/"
	oidcLoginPath     = "/auth/login"
	oidcCallbackPath  = "/auth/callback"
	oidcLogoutPath    = "/logout"
	oidcLoggedOutPath = "/auth/logged-out"
	oidcRetryAfter    = 5 * time.Second // a failed discovery is not retried sooner
	// oidcWriteTimeout covers the provider round trips of a login (discovery, code exchange, jwks), longer
	// than the server's write timeout
	oidcWriteTimeout = 45 * time.Second
)

// cookie purposes, mixed into the signature so a cookie of one kind never verifies as the other
const (
	purposeSession = "session"
	purposeState   = "state"
)

// oidcAuth guards the web UI with an OpenID Connect login (authorization code with PKCE). Sessions are
// cookies signed with a key generated at startup, so a restart signs everyone out; logout revokes the
// session id until it would expire. The allow list is checked once, at login.
type oidcAuth struct {
	cfg        config.OIDCSettings
	key        []byte
	client     *http.Client
	publicBase string // cfg.URL without a trailing slash
	publicHost string // its host, lower case, without the default port

	fetchMu  sync.Mutex // serializes discovery, so waiters share one fetch instead of each starting one
	mu       sync.Mutex // guards the fields below
	provider *oidcProvider
	failedAt time.Time // last failed discovery, see oidcRetryAfter
	failErr  error
	revoked  map[string]int64 // logged out session id -> its expiry
}

// oidcProvider is what discovery yields
type oidcProvider struct {
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
}

// oidcSession is the payload of the session cookie
type oidcSession struct {
	ID      string `json:"i"`
	Sub     string `json:"s"`
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
	Sub           string     `json:"sub"`
	Email         string     `json:"email"`
	EmailVerified flexBool   `json:"email_verified"`
	Username      string     `json:"preferred_username"`
	Roles         stringList `json:"roles"`
	Groups        stringList `json:"groups"`
}

// flexBool decodes a JSON bool or the strings "true"/"false", as some providers send email_verified
type flexBool bool

// UnmarshalJSON implements json.Unmarshaler
func (b *flexBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("can't decode bool claim: %w", err)
	}
	switch t := v.(type) {
	case bool:
		*b = flexBool(t)
	case string:
		*b = flexBool(strings.EqualFold(t, "true"))
	default:
		*b = false
	}
	return nil
}

// stringList decodes a JSON array of strings or a single string, as some providers send a lone role or group
type stringList []string

// UnmarshalJSON implements json.Unmarshaler
func (l *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*l = stringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("can't decode list claim: %w", err)
	}
	*l = many
	return nil
}

func newOIDCAuth(cfg config.OIDCSettings) (*oidcAuth, error) {
	if err := config.ValidateOIDC(cfg); err != nil {
		return nil, fmt.Errorf("invalid oidc settings: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("can't generate session key: %w", err)
	}
	public, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid oidc url: %w", err)
	}
	return &oidcAuth{cfg: cfg, key: key, client: &http.Client{Timeout: 10 * time.Second}, revoked: map[string]int64{},
		publicBase: strings.TrimSuffix(cfg.URL, "/"), publicHost: canonicalHost(public.Host)}, nil
}

// discover fetches the provider metadata on first use and keeps it, so the web UI starts even while the
// issuer is unreachable. One fetch runs at a time and others wait for its result; a failure is returned
// without a new fetch for oidcRetryAfter, so a down issuer costs one outbound request per interval.
func (a *oidcAuth) discover(ctx context.Context) (*oidcProvider, error) {
	if p, err, ok := a.known(); ok {
		return p, err
	}
	a.fetchMu.Lock()
	defer a.fetchMu.Unlock()
	if p, err, ok := a.known(); ok { // fetched or failed while this request waited
		return p, err
	}
	// detached from the request: a client that goes away must not fail, and cache the failure of, the fetch
	// other requests wait on. a.client carries the timeout
	p, err := a.fetchProvider(context.WithoutCancel(ctx))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.failedAt, a.failErr = time.Now(), err
		return nil, err
	}
	a.provider = p
	return p, nil
}

// known returns the discovered provider, or the recent discovery failure, and whether either is set
func (a *oidcAuth) known() (*oidcProvider, error, bool) { //nolint:revive // the bool says whether to fetch
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil, true
	}
	if a.failErr != nil && time.Since(a.failedAt) < oidcRetryAfter {
		return nil, a.failErr, true
	}
	return nil, nil, false
}

// fetchProvider runs the discovery request and builds the client config from it
func (a *oidcAuth) fetchProvider(ctx context.Context) (*oidcProvider, error) {

	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, a.client), a.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("can't read oidc provider metadata: %w", err)
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if slices.ContainsFunc(a.cfg.Allow, func(s string) bool { return strings.HasPrefix(s, "group:") }) {
		scopes = append(scopes, "groups") // not a standard scope, asked for only when the allow list needs it
	}
	return &oidcProvider{
		endSession: meta.EndSession,
		verifier:   provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     a.cfg.ClientID,
			ClientSecret: a.cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  a.publicBase + oidcCallbackPath,
			Scopes:       scopes,
		},
	}, nil
}

// middleware passes requests with a valid session; anything else is sent to the login page when it is a
// page load, or refused with 401 otherwise. It is not installed on the login routes, see Server.Run.
func (a *oidcAuth) middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.redirectToPublicHost(w, r) {
			return
		}
		if _, ok := a.session(r); ok {
			h.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("HX-Request") == "true" {
			// an htmx request is a fragment of the page the user is on, so return there after the login
			login := oidcLoginPath
			if u, err := url.Parse(r.Header.Get("HX-Current-URL")); err == nil && u.Path != "" {
				login += "?rd=" + url.QueryEscape(u.RequestURI())
			}
			w.Header().Set("HX-Redirect", login)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, oidcLoginPath+"?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// loginHandler starts the authorization code flow, keeping state, nonce and PKCE verifier in a signed cookie
// named after the state, so logins started in several tabs don't overwrite each other. Abandoned logins
// would pile up such cookies until the request headers grow too big, so only the newest few are kept.
func (a *oidcAuth) loginHandler(w http.ResponseWriter, r *http.Request) {
	if a.redirectToPublicHost(w, r) {
		return
	}
	extendWriteDeadline(w)
	p, err := a.discover(r.Context())
	if err != nil {
		log.Printf("[WARN] %v", err)
		http.Error(w, "login provider unavailable", http.StatusBadGateway)
		return
	}
	st := oidcState{State: rand.Text(), Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(),
		Return: localPath(r.URL.Query().Get("rd")), Expires: time.Now().Add(oidcStateTTL).Unix()}
	value, err := a.sign(purposeState, st)
	if err != nil {
		http.Error(w, "can't start login", http.StatusInternalServerError)
		return
	}
	a.dropOldStates(w, r)
	setCookie(w, oidcStatePrefix+st.State, value, oidcStatePath, oidcStateTTL)
	authURL := p.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// callbackHandler finishes the flow: checks state, exchanges the code, verifies the id token and its nonce,
// matches the account against the allow list and issues the session cookie
func (a *oidcAuth) callbackHandler(w http.ResponseWriter, r *http.Request) {
	extendWriteDeadline(w)
	q := r.URL.Query()
	var st oidcState
	c, err := r.Cookie(oidcStatePrefix + q.Get("state"))
	if err != nil || !a.verify(purposeState, c.Value, &st) || time.Now().Unix() > st.Expires {
		http.Error(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	setCookie(w, c.Name, "", oidcStatePath, 0)
	// the cookie is found by the state, so this guards against a cookie signed for another state
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		http.Error(w, "login state mismatch", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		http.Error(w, "login failed: "+e, http.StatusForbidden)
		return
	}

	p, err := a.discover(r.Context())
	if err != nil {
		log.Printf("[WARN] %v", err)
		http.Error(w, "login provider unavailable", http.StatusBadGateway)
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.client)
	token, err := p.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
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
	idToken, err := p.verifier.Verify(ctx, rawID)
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
		log.Printf("[WARN] can't decode oidc id token claims: %v", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	if claims.Sub == "" {
		http.Error(w, "login failed: no subject", http.StatusForbidden)
		return
	}
	if !a.allowed(claims) {
		log.Printf("[WARN] oidc login refused for sub=%s email=%s", claims.Sub, claims.Email)
		http.Error(w, "account not allowed", http.StatusForbidden)
		return
	}

	value, err := a.sign(purposeSession, oidcSession{ID: rand.Text(), Sub: claims.Sub,
		Expires: time.Now().Add(oidcSessionTTL).Unix()})
	if err != nil {
		http.Error(w, "can't create session", http.StatusInternalServerError)
		return
	}
	setCookie(w, oidcSessionCookie, value, "/", oidcSessionTTL)
	log.Printf("[INFO] oidc login: %s (sub=%s)", cmp.Or(claims.Username, claims.Email, claims.Sub), claims.Sub)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

// logoutHandler (POST, so the router's cross-origin protection covers it) drops the session and hands over
// to the provider's logout page, which ends the provider session too; otherwise the next request would sign
// straight back in. The navbar posts it with htmx, which follows HX-Redirect but not a cross-origin 302.
func (a *oidcAuth) logoutHandler(w http.ResponseWriter, r *http.Request) {
	extendWriteDeadline(w)
	if s, ok := a.session(r); ok {
		a.revoke(s)
	}
	setCookie(w, oidcSessionCookie, "", "/", 0)
	// without the provider's logout the next request would sign straight back in, so a provider without
	// one gets a local page that does not trigger a login
	target := oidcLoggedOutPath
	if p, err := a.discover(r.Context()); err == nil && p.endSession != "" {
		if u, perr := url.Parse(p.endSession); perr == nil {
			q := u.Query()
			q.Set("client_id", a.cfg.ClientID)
			u.RawQuery = q.Encode()
			target = u.String()
		}
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// logoutPageHandler answers GET /logout, left in bookmarks and pages cached from before logout was a POST,
// with a page that posts it; logging out on a GET would let any site sign the admin out.
// TODO: remove with the basic auth GET /logout once such bookmarks and cached pages are gone
func (a *oidcAuth) logoutPageHandler(w http.ResponseWriter, _ *http.Request) {
	writeOIDCPage(w, "Sign out of tg-spam?", `<form method="post" action="`+oidcLogoutPath+`"><button>Sign out</button></form>`)
}

// loggedOutHandler is where logout ends when the provider has no logout endpoint
func (a *oidcAuth) loggedOutHandler(w http.ResponseWriter, _ *http.Request) {
	writeOIDCPage(w, "Signed out of tg-spam.", `<a href="/">Sign in again</a>`)
}

// redirectToPublicHost sends a request for another host (a tailnet address, another proxy name) to the
// public url: the login cookies are host-bound and the provider calls back on the public url only. A proxy
// that rewrites Host is recognized by X-Forwarded-Host; trusting it is safe here, it only decides whether to
// redirect, and the target is always the configured url.
func (a *oidcAuth) redirectToPublicHost(w http.ResponseWriter, r *http.Request) bool {
	host := cmp.Or(r.Header.Get("X-Forwarded-Host"), r.Host)
	if canonicalHost(host) == a.publicHost {
		return false
	}
	target := a.publicBase + r.URL.RequestURI()
	switch {
	case r.Header.Get("HX-Request") == "true":
		w.Header().Set("HX-Redirect", target) // an XHR can't follow a cross-origin redirect
		w.WriteHeader(http.StatusMisdirectedRequest)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		// the host comes from the configured public url; the request part can only add a path to it
		http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // not an open redirect, see above
	default:
		http.Error(w, "use "+a.publicHost, http.StatusMisdirectedRequest)
	}
	return true
}

// canonicalHost lower-cases a host and drops the default https port, which browsers leave out of Host
func canonicalHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ":443")
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
			if bool(c.EmailVerified) && strings.EqualFold(c.Email, value) {
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

// session returns the session from a valid, unexpired, not revoked session cookie
func (a *oidcAuth) session(r *http.Request) (oidcSession, bool) {
	var s oidcSession
	c, err := r.Cookie(oidcSessionCookie)
	if err != nil || !a.verify(purposeSession, c.Value, &s) || s.ID == "" || s.Sub == "" ||
		time.Now().Unix() > s.Expires {
		return oidcSession{}, false
	}
	a.mu.Lock()
	_, revoked := a.revoked[s.ID]
	a.mu.Unlock()
	if revoked {
		return oidcSession{}, false
	}
	return s, true
}

// revoke keeps a logged out session id refused until the session would expire, pruning expired entries
func (a *oidcAuth) revoke(s oidcSession) {
	now := time.Now().Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, exp := range a.revoked {
		if exp < now {
			delete(a.revoked, id)
		}
	}
	a.revoked[s.ID] = s.Expires
}

// dropOldStates deletes the login cookies of earlier, unfinished logins beyond the newest oidcStateMax-1,
// making room for the one being set
func (a *oidcAuth) dropOldStates(w http.ResponseWriter, r *http.Request) {
	type pending struct {
		name    string
		expires int64
	}
	var states []pending
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, oidcStatePrefix) {
			continue
		}
		var st oidcState
		if !a.verify(purposeState, c.Value, &st) {
			setCookie(w, c.Name, "", oidcStatePath, 0)
			continue
		}
		states = append(states, pending{name: c.Name, expires: st.Expires})
	}
	slices.SortFunc(states, func(x, y pending) int { return cmp.Compare(y.expires, x.expires) })
	for i, st := range states {
		if i >= oidcStateMax-1 {
			setCookie(w, st.name, "", oidcStatePath, 0)
		}
	}
}

// sign encodes v as base64url(json) "." base64url(mac over purpose and payload)
func (a *oidcAuth) sign(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("can't marshal cookie payload: %w", err)
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(a.mac(purpose, p)), nil
}

// verify checks that value was made by sign for the same purpose and decodes its payload into v
func (a *oidcAuth) verify(purpose, value string, v any) bool {
	p, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || subtle.ConstantTimeCompare(got, a.mac(purpose, p)) != 1 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return false
	}
	return json.Unmarshal(payload, v) == nil
}

// mac is a keyed blake3 hash of purpose, a zero byte and payload
func (a *oidcAuth) mac(purpose, payload string) []byte {
	m := blake3.New(32, a.key)
	_, _ = m.Write([]byte(purpose))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(payload))
	return m.Sum(nil)
}

// setCookie sets a cookie living for ttl, or deletes it when ttl is not positive. Secure is unconditional:
// ValidateOIDC only accepts an https public url
func setCookie(w http.ResponseWriter, name, value, cookiePath string, ttl time.Duration) {
	maxAge := -1
	if ttl > 0 {
		maxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: cookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// extendWriteDeadline lifts the server's write timeout for a handler that waits on the provider
func extendWriteDeadline(w http.ResponseWriter) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(oidcWriteTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		log.Printf("[WARN] can't extend write deadline: %v", err)
	}
}

// localPath keeps a post-login return target only when it is a path on this host. It returns the cleaned
// path, as http.Redirect cleans it too: checking the raw value would let "/./\host" through and become
// "/\host", which browsers treat as "//host". Backslashes, also percent-encoded, are refused outright.
func localPath(p string) string {
	u, err := url.Parse(p)
	if err != nil || strings.Contains(p, "\\") || strings.Contains(u.Path, "\\") || u.Scheme != "" || u.Host != "" ||
		u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	clean := path.Clean(u.EscapedPath())
	if strings.HasPrefix(clean, "//") {
		return "/"
	}
	if u.RawQuery != "" {
		clean += "?" + u.RawQuery
	}
	return clean
}

// writeOIDCPage writes a minimal html page; title and body are fixed strings, never user input
func writeOIDCPage(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// no form-action: the logout form's 303 goes on to the provider, and form-action applies to that redirect
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, "<!doctype html><title>tg-spam</title><p>%s</p>%s\n", title, body)
}
