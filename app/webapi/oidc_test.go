package webapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-pkgz/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/config"
	"github.com/umputun/tg-spam/app/webapi/mocks"
)

// fakeIssuer is a minimal OIDC provider: discovery, jwks and a token endpoint that checks the PKCE verifier
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	challenge string         // code_challenge of the last authorize request
	nonce     string         // nonce put into the id token, defaults to the one from the authorize request
	claims    map[string]any // extra id token claims
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"end_session_endpoint":                  f.srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.PostForm.Get("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "tg-spam", "sub": "u1", "nonce": f.nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
		maps.Copy(claims, f.claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer",
			"id_token": f.sign(t, claims)})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	unsigned := enc(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newTestOIDC returns the auth wired to the fake issuer and a handler with the middleware and the login routes
func newTestOIDC(t *testing.T, f *fakeIssuer, allow ...string) (*oidcAuth, http.Handler) {
	t.Helper()
	a, err := newOIDCAuth(config.OIDCSettings{Issuer: f.srv.URL, ClientID: "tg-spam", ClientSecret: "secret",
		URL: "https://tg.example.com", Allow: allow})
	require.NoError(t, err)
	a.client = f.srv.Client()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidcLoginPath, a.loginHandler)
	mux.HandleFunc("GET "+oidcCallbackPath, a.callbackHandler)
	mux.HandleFunc("POST /logout", a.logoutHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := a.middleware(mux)
	return a, h
}

// login runs the login redirect and returns the state cookie and the authorize request parameters
func login(t *testing.T, f *fakeIssuer, h http.Handler, rd string) (*http.Cookie, url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidcLoginPath+"?rd="+url.QueryEscape(rd), http.NoBody))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	assert.Equal(t, f.srv.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "https://tg.example.com/auth/callback", q.Get("redirect_uri"))
	f.mu.Lock()
	f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	f.mu.Unlock()
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, oidcStatePrefix+q.Get("state"), cookies[0].Name)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
	return cookies[0], q
}

func callback(h http.Handler, state *http.Cookie, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?"+query, http.NoBody)
	if state != nil {
		req.AddCookie(state)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcSessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestOIDC_Middleware(t *testing.T) {
	_, h := newTestOIDC(t, newFakeIssuer(t), "role:admin")

	t.Run("page load redirects to login", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/manage_users?x=1", http.NoBody))
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/auth/login?rd=%2Fmanage_users%3Fx%3D1", rec.Header().Get("Location"))
	})
	t.Run("htmx request returns to the page it was made from", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dm-users", http.NoBody)
		req.Header.Set("HX-Request", "true")
		req.Header.Set("HX-Current-URL", "https://tg.example.com/list_settings?tab=1")
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "/auth/login?rd=%2Flist_settings%3Ftab%3D1", rec.Header().Get("HX-Redirect"))
	})
	t.Run("htmx request without current url", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/check", http.NoBody)
		req.Header.Set("HX-Request", "true")
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "/auth/login", rec.Header().Get("HX-Redirect"))
	})
	t.Run("post is refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/check", strings.NewReader("{}")))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("basic auth is not accepted", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader("{}"))
		req.SetBasicAuth("tg-spam", "secret")
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestOIDC_LoginFlow(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		claims  map[string]any
		allowed bool
	}{
		{"role", []string{"role:admin"}, map[string]any{"roles": []string{"user", "admin"}}, true},
		{"single role as a string", []string{"role:admin"}, map[string]any{"roles": "admin"}, true},
		{"email_verified as a string", []string{"email:a@example.com"},
			map[string]any{"email": "a@example.com", "email_verified": "true"}, true},
		{"email_verified false as a string", []string{"email:a@example.com"},
			map[string]any{"email": "a@example.com", "email_verified": "false"}, false},
		{"group", []string{"group:ops"}, map[string]any{"groups": []string{"ops"}}, true},
		{"verified email", []string{"email:A@example.com"}, map[string]any{"email": "a@example.com", "email_verified": true}, true},
		{"unverified email", []string{"email:a@example.com"}, map[string]any{"email": "a@example.com"}, false},
		{"sub", []string{"sub:u1"}, nil, true},
		{"no matching role", []string{"role:admin"}, map[string]any{"roles": []string{"user"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIssuer(t)
			f.claims = tc.claims
			_, h := newTestOIDC(t, f, tc.allow...)
			state, q := login(t, f, h, "/manage_users")

			rec := callback(h, state, "code=good-code&state="+url.QueryEscape(q.Get("state")))
			if !tc.allowed {
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Nil(t, sessionCookie(rec))
				return
			}
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
			assert.Equal(t, "/manage_users", rec.Header().Get("Location"))
			sess := sessionCookie(rec)
			require.NotNil(t, sess)

			req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader("{}"))
			req.AddCookie(sess)
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestOIDC_CallbackRejects(t *testing.T) {
	f := newFakeIssuer(t)
	f.claims = map[string]any{"roles": []string{"admin"}}
	a, h := newTestOIDC(t, f, "role:admin")

	t.Run("no state cookie", func(t *testing.T) {
		_, q := login(t, f, h, "/")
		assert.Equal(t, http.StatusBadRequest, callback(h, nil, "code=good-code&state="+q.Get("state")).Code)
	})
	t.Run("unknown state", func(t *testing.T) {
		state, _ := login(t, f, h, "/")
		assert.Equal(t, http.StatusBadRequest, callback(h, state, "code=good-code&state=other").Code)
	})
	t.Run("cookie signed for another state", func(t *testing.T) {
		state, _ := login(t, f, h, "/")
		moved := &http.Cookie{Name: oidcStatePrefix + "other", Value: state.Value}
		assert.Equal(t, http.StatusBadRequest, callback(h, moved, "code=good-code&state=other").Code)
	})
	t.Run("expired state cookie", func(t *testing.T) {
		_, q := login(t, f, h, "/")
		value, err := a.sign(oidcState{State: q.Get("state"), Expires: time.Now().Add(-time.Second).Unix()})
		require.NoError(t, err)
		rec := callback(h, &http.Cookie{Name: oidcStatePrefix + q.Get("state"), Value: value},
			"code=good-code&state="+q.Get("state"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
	t.Run("logins in two tabs", func(t *testing.T) {
		first, q1 := login(t, f, h, "/first")
		f.mu.Lock()
		challenge, nonce := f.challenge, f.nonce
		f.mu.Unlock()
		_, _ = login(t, f, h, "/second") // overwrites the fake issuer's record, not the first tab's cookie
		f.mu.Lock()
		f.challenge, f.nonce = challenge, nonce
		f.mu.Unlock()
		rec := callback(h, first, "code=good-code&state="+q1.Get("state"))
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		assert.Equal(t, "/first", rec.Header().Get("Location"))
	})
	t.Run("wrong code", func(t *testing.T) {
		state, q := login(t, f, h, "/")
		assert.Equal(t, http.StatusForbidden, callback(h, state, "code=bad&state="+q.Get("state")).Code)
	})
	t.Run("provider error", func(t *testing.T) {
		state, q := login(t, f, h, "/")
		assert.Equal(t, http.StatusForbidden, callback(h, state, "error=access_denied&state="+q.Get("state")).Code)
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		state, q := login(t, f, h, "/")
		f.mu.Lock()
		f.nonce = "other"
		f.mu.Unlock()
		rec := callback(h, state, "code=good-code&state="+q.Get("state"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Nil(t, sessionCookie(rec))
	})
	t.Run("open redirect target is dropped", func(t *testing.T) {
		state, q := login(t, f, h, "//evil.example.com/x")
		rec := callback(h, state, "code=good-code&state="+q.Get("state"))
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/", rec.Header().Get("Location"))
	})
}

func TestOIDC_Session(t *testing.T) {
	a, h := newTestOIDC(t, newFakeIssuer(t), "role:admin")
	do := func(c *http.Cookie) int {
		req := httptest.NewRequest(http.MethodPost, "/check", http.NoBody)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	valid, err := a.sign(oidcSession{Sub: "u1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, do(&http.Cookie{Name: oidcSessionCookie, Value: valid}))

	expired, err := a.sign(oidcSession{Sub: "u1", Expires: time.Now().Add(-time.Second).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: expired}))

	payload, _, _ := strings.Cut(valid, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"s":"u2","e":9999999999}`)) + "." + strings.Split(valid, ".")[1]
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: forged}))
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: payload}))

	other, err := newOIDCAuth(a.cfg) // another process has another key
	require.NoError(t, err)
	foreign, err := other.sign(oidcSession{Sub: "u1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: foreign}))
}

func TestOIDC_Logout(t *testing.T) {
	f := newFakeIssuer(t)
	_, h := newTestOIDC(t, f, "role:admin")
	checkCleared := func(rec *httptest.ResponseRecorder) {
		cookies := rec.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, oidcSessionCookie, cookies[0].Name)
		assert.Empty(t, cookies[0].Value)
		assert.Negative(t, cookies[0].MaxAge)
	}

	t.Run("form post", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", http.NoBody))
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, f.srv.URL+"/logout", rec.Header().Get("Location"))
		checkCleared(rec)
	})
	t.Run("htmx post", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
		req.Header.Set("HX-Request", "true")
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, f.srv.URL+"/logout", rec.Header().Get("HX-Redirect"))
		assert.Empty(t, rec.Header().Get("Location"))
		checkCleared(rec)
	})
	t.Run("other methods stay behind the login", func(t *testing.T) {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/logout", http.NoBody),
			httptest.NewRequest(http.MethodPost, oidcLoginPath, http.NoBody),
			httptest.NewRequest(http.MethodPost, oidcCallbackPath, http.NoBody),
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.NotEqual(t, http.StatusOK, rec.Code, "%s %s", req.Method, req.URL.Path)
			assert.NotEqual(t, "ok", rec.Body.String(), "catch-all must not be reached")
		}
	})
}

func TestOIDC_Scopes(t *testing.T) {
	f := newFakeIssuer(t)
	_, h := newTestOIDC(t, f, "role:admin")
	_, q := login(t, f, h, "/")
	assert.Equal(t, "openid profile email", q.Get("scope"))

	_, h = newTestOIDC(t, f, "role:admin", "group:ops")
	_, q = login(t, f, h, "/")
	assert.Equal(t, "openid profile email groups", q.Get("scope"))
}

func TestLocalPath(t *testing.T) {
	tests := map[string]string{
		"":                    "/",
		"/":                   "/",
		"/manage_users?x=1":   "/manage_users?x=1",
		"//evil.com":          "/",
		"/\\evil.com":         "/",
		"https://evil.com/":   "/",
		"manage_users":        "/",
		"/./\\evil.com":       "/",
		"/a/../\\evil.com":    "/",
		"/%5Cevil.com":        "/",
		"/a/../%5Cevil.com":   "/",
		"/.//evil.com":        "/evil.com",
		"/%2F%2Fevil.com/abc": "/%2F%2Fevil.com/abc",
		"/a/./b/../c?d=1":     "/a/c?d=1",
	}
	for in, want := range tests {
		assert.Equal(t, want, localPath(in), in)
	}
}

func TestServer_RunOIDC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hash, err := rest.GenerateBcryptHash("test")
	require.NoError(t, err)
	srv := NewServer(Config{ListenAddr: ":9881", Version: "dev", Detector: &mocks.DetectorMock{},
		SpamFilter: &mocks.SpamFilterMock{}, AuthHash: hash,
		OIDC: config.OIDCSettings{Issuer: "https://auth.example.invalid", ClientID: "tg-spam", ClientSecret: "s",
			URL: "https://tg.example.com", Allow: []string{"role:admin"}}})
	done := make(chan struct{})
	go func() {
		assert.NoError(t, srv.Run(ctx))
		close(done)
	}()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, target string, basicAuth bool) *http.Response {
		req, err := http.NewRequest(method, "http://localhost:9881"+target, http.NoBody)
		require.NoError(t, err)
		if basicAuth {
			req.SetBasicAuth("tg-spam", "test")
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp
	}
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://localhost:9881/ping")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond, "server did not start")

	for _, target := range []string{"/", "/manage_users", "/styles.css", "/logout", "/settings"} {
		resp := do(http.MethodGet, target, false)
		assert.Equal(t, http.StatusFound, resp.StatusCode, target)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), oidcLoginPath+"?rd="), target)
	}
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodPost, "/check", true).StatusCode, "basic auth is off")
	assert.Equal(t, http.StatusBadGateway, do(http.MethodGet, oidcLoginPath, false).StatusCode, "issuer unreachable")

	resp := do(http.MethodPost, "/logout", false)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"), "falls back to / without discovery")

	cancel()
	<-done
}
