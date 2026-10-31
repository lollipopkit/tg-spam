package webapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-pkgz/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/config"
	"github.com/umputun/tg-spam/app/openid/openidtest"
	"github.com/umputun/tg-spam/app/webapi/mocks"
)

// newTestOIDC returns the auth wired to the fake issuer and a handler with the middleware and the login routes
func newTestOIDC(t *testing.T, f *openidtest.Issuer, allow ...string) (*oidcAuth, http.Handler) {
	t.Helper()
	a, err := newOIDCAuth(config.OIDCSettings{Issuer: f.Srv.URL, ClientID: "tg-spam", ClientSecret: "secret",
		URL: "https://example.com", Allow: allow})
	require.NoError(t, err)
	a.idp.HTTP = f.Srv.Client()
	// same layout as Server.Run: login routes outside the guarded handler, everything else inside
	guarded := http.NewServeMux()
	guarded.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidcLoginPath, a.loginHandler)
	mux.HandleFunc("GET "+oidcCallbackPath, a.callbackHandler)
	mux.HandleFunc("POST "+oidcLogoutPath, a.logoutHandler)
	mux.HandleFunc("GET "+oidcLogoutPath, a.logoutPageHandler)
	mux.HandleFunc("GET "+oidcLoggedOutPath, a.loggedOutHandler)
	mux.Handle("/", a.middleware(guarded))
	return a, mux
}

// login runs the login redirect and returns the state cookie and the authorize request parameters
func login(t *testing.T, f *openidtest.Issuer, h http.Handler, rd string) (*http.Cookie, url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidcLoginPath+"?rd="+url.QueryEscape(rd), http.NoBody))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	q := f.Authorize(t, rec.Header().Get("Location"))
	assert.Equal(t, "https://example.com/auth/callback", q.Get("redirect_uri"))
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
	_, h := newTestOIDC(t, openidtest.New(t, "tg-spam"), "role:admin")

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
		req.Header.Set("HX-Current-URL", "https://example.com/list_settings?tab=1")
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
	t.Run("another host is sent to the public url", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://100.64.0.1:8080/manage_users?x=1", http.NoBody)
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "https://example.com/manage_users?x=1", rec.Header().Get("Location"))

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://100.64.0.1:8080"+oidcLoginPath, http.NoBody))
		assert.Equal(t, "https://example.com"+oidcLoginPath, rec.Header().Get("Location"), "login too")

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://100.64.0.1:8080/check", http.NoBody))
		assert.Equal(t, http.StatusMisdirectedRequest, rec.Code)

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "http://100.64.0.1:8080/", http.NoBody))
		assert.Equal(t, http.StatusFound, rec.Code, "head is redirected like get")

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "http://100.64.0.1:8080/dm-users", http.NoBody)
		req.Header.Set("HX-Request", "true")
		h.ServeHTTP(rec, req)
		assert.Equal(t, "https://example.com/dm-users", rec.Header().Get("HX-Redirect"))
		assert.Empty(t, rec.Header().Get("Location"))
	})
	t.Run("public host behind a proxy or with the default port is not redirected", func(t *testing.T) {
		for _, req := range []*http.Request{
			func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/x", http.NoBody)
				r.Header.Set("X-Forwarded-Host", "Example.com")
				return r
			}(),
			httptest.NewRequest(http.MethodGet, "https://example.com:443/x", http.NoBody),
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, "/auth/login?rd=%2Fx", rec.Header().Get("Location"), req.Host)
		}
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
			f := openidtest.New(t, "tg-spam")
			f.SetClaims(tc.claims)
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
	f := openidtest.New(t, "tg-spam")
	f.SetClaims(map[string]any{"roles": []string{"admin"}})
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
		value, err := a.sign(purposeState, oidcState{State: q.Get("state"), Expires: time.Now().Add(-time.Second).Unix()})
		require.NoError(t, err)
		rec := callback(h, &http.Cookie{Name: oidcStatePrefix + q.Get("state"), Value: value},
			"code=good-code&state="+q.Get("state"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
	t.Run("logins in two tabs", func(t *testing.T) {
		first, q1 := login(t, f, h, "/first")
		challenge, nonce := f.Pending()
		_, _ = login(t, f, h, "/second") // overwrites the fake issuer's record, not the first tab's cookie
		f.SetPending(challenge, nonce)
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
		f.SetNonce("other")
		rec := callback(h, state, "code=good-code&state="+q.Get("state"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Nil(t, sessionCookie(rec))
	})
	t.Run("older login cookies are dropped", func(t *testing.T) {
		cookies := make([]*http.Cookie, 0, 6)
		for i := range 5 {
			value, err := a.sign(purposeState, oidcState{State: fmt.Sprintf("s%d", i), Expires: time.Now().Add(time.Duration(i) * time.Second).Unix()})
			require.NoError(t, err)
			cookies = append(cookies, &http.Cookie{Name: oidcStatePrefix + fmt.Sprintf("s%d", i), Value: value})
		}
		cookies = append(cookies, &http.Cookie{Name: oidcStatePrefix + "forged", Value: "x.y"})
		req := httptest.NewRequest(http.MethodGet, oidcLoginPath, http.NoBody)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)
		var deleted, set []string
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 {
				deleted = append(deleted, c.Name)
			} else {
				set = append(set, c.Name)
			}
		}
		assert.ElementsMatch(t, []string{oidcStatePrefix + "s0", oidcStatePrefix + "s1", oidcStatePrefix + "s2",
			oidcStatePrefix + "forged"}, deleted, "keeps s3 and s4, the newest two, next to the new one")
		assert.Len(t, set, 1)
	})
	t.Run("open redirect target is dropped", func(t *testing.T) {
		state, q := login(t, f, h, "//evil.example.com/x")
		rec := callback(h, state, "code=good-code&state="+q.Get("state"))
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/", rec.Header().Get("Location"))
	})
}

func TestOIDC_Session(t *testing.T) {
	a, h := newTestOIDC(t, openidtest.New(t, "tg-spam"), "role:admin")
	do := func(c *http.Cookie) int {
		req := httptest.NewRequest(http.MethodPost, "/check", http.NoBody)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	valid, err := a.sign(purposeSession, oidcSession{ID: "id1", Sub: "u1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, do(&http.Cookie{Name: oidcSessionCookie, Value: valid}))

	expired, err := a.sign(purposeSession, oidcSession{ID: "id1", Sub: "u1", Expires: time.Now().Add(-time.Second).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: expired}))

	payload, _, _ := strings.Cut(valid, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"i":"x","s":"u2","e":9999999999}`)) + "." + strings.Split(valid, ".")[1]
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: forged}))
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: payload}))

	state, err := a.sign(purposeState, oidcState{State: "s", Nonce: "n", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: state}),
		"a login cookie must not pass as a session")

	noSub, err := a.sign(purposeSession, oidcSession{ID: "id1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: noSub}))

	other, err := newOIDCAuth(a.cfg) // another process has another key
	require.NoError(t, err)
	foreign, err := other.sign(purposeSession, oidcSession{ID: "id1", Sub: "u1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, do(&http.Cookie{Name: oidcSessionCookie, Value: foreign}))
}

func TestOIDC_Logout(t *testing.T) {
	f := openidtest.New(t, "tg-spam")
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
		assert.Equal(t, f.Srv.URL+"/logout?client_id=tg-spam", rec.Header().Get("Location"))
		checkCleared(rec)
	})
	t.Run("logout revokes the session", func(t *testing.T) {
		a, guarded := newTestOIDC(t, f, "role:admin")
		value, err := a.sign(purposeSession, oidcSession{ID: "id1", Sub: "u1", Expires: time.Now().Add(time.Hour).Unix()})
		require.NoError(t, err)
		sess := &http.Cookie{Name: oidcSessionCookie, Value: value}
		get := func() int {
			req := httptest.NewRequest(http.MethodGet, "/manage_users", http.NoBody)
			req.AddCookie(sess)
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			return rec.Code
		}
		require.Equal(t, http.StatusOK, get())
		req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
		req.AddCookie(sess)
		guarded.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, http.StatusFound, get(), "a copy of the logged out cookie is refused")
	})
	t.Run("htmx post", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
		req.Header.Set("HX-Request", "true")
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, f.Srv.URL+"/logout?client_id=tg-spam", rec.Header().Get("HX-Redirect"))
		assert.Empty(t, rec.Header().Get("Location"))
		checkCleared(rec)
	})
	t.Run("provider without logout endpoint ends on a local page", func(t *testing.T) {
		nf := openidtest.New(t, "tg-spam")
		nf.SetNoLogout()
		_, nh := newTestOIDC(t, nf, "role:admin")
		rec := httptest.NewRecorder()
		nh.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", http.NoBody))
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, oidcLoggedOutPath, rec.Header().Get("Location"))
		rec = httptest.NewRecorder()
		nh.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidcLoggedOutPath, http.NoBody))
		assert.Equal(t, http.StatusOK, rec.Code, "the page must not trigger a login")
		assert.Contains(t, rec.Body.String(), "Signed out")
	})
	t.Run("get shows a page that posts the logout", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", http.NoBody))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `<form method="post" action="/logout">`)
		assert.NotContains(t, rec.Header().Get("Content-Security-Policy"), "form-action",
			"form-action would block the 303 to the provider")
		assert.Empty(t, rec.Result().Cookies(), "a get does not log out")
	})
	t.Run("other methods and encoded paths stay behind the login", func(t *testing.T) {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodPut, "/logout", http.NoBody),
			httptest.NewRequest(http.MethodPost, oidcLoginPath, http.NoBody),
			httptest.NewRequest(http.MethodPost, oidcCallbackPath, http.NoBody),
			httptest.NewRequest(http.MethodGet, "/auth%2Flogin", http.NoBody),
			httptest.NewRequest(http.MethodGet, "/auth%2Fcallback", http.NoBody),
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.NotEqual(t, http.StatusOK, rec.Code, "%s %s", req.Method, req.URL.Path)
			assert.NotEqual(t, "ok", rec.Body.String(), "catch-all must not be reached")
		}
	})
}

func TestOIDC_Scopes(t *testing.T) {
	f := openidtest.New(t, "tg-spam")
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
	// requests carry the public host, as they do behind the proxy
	done := make(chan struct{})
	go func() {
		assert.NoError(t, srv.Run(ctx))
		close(done)
	}()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, target string, basicAuth bool) *http.Response {
		req, err := http.NewRequest(method, "http://localhost:9881"+target, http.NoBody)
		require.NoError(t, err)
		req.Host = "tg.example.com"
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

	for _, target := range []string{"/", "/manage_users", "/styles.css", "/settings", "/auth%2Flogin"} {
		resp := do(http.MethodGet, target, false)
		assert.Equal(t, http.StatusFound, resp.StatusCode, target)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), oidcLoginPath+"?rd="), target)
	}
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodPost, "/check", true).StatusCode, "basic auth is off")
	assert.Equal(t, http.StatusBadGateway, do(http.MethodGet, oidcLoginPath, false).StatusCode, "issuer unreachable")

	resp := do(http.MethodPost, "/logout", false)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, oidcLoggedOutPath, resp.Header.Get("Location"), "falls back to the local page without discovery")
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/logout", false).StatusCode, "logout confirmation page")

	cancel()
	<-done
}
