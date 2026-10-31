package openid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/openid/openidtest"
)

func newTestClient(t *testing.T, f *openidtest.Issuer) *Client {
	t.Helper()
	c := New(Config{Issuer: f.Srv.URL, ClientID: f.ClientID, ClientSecret: "secret",
		RedirectURL: "https://example.com/cb", Scopes: []string{"profile"}})
	c.HTTP = f.Srv.Client()
	return c
}

// authorize runs the authorization redirect of a fresh login against the issuer
func authorize(t *testing.T, f *openidtest.Issuer, c *Client) Login {
	t.Helper()
	p, err := c.Discover(t.Context())
	require.NoError(t, err)
	l := NewLogin()
	q := f.Authorize(t, p.AuthCodeURL(l))
	assert.Equal(t, l.State, q.Get("state"))
	assert.Equal(t, "https://example.com/cb", q.Get("redirect_uri"))
	assert.Equal(t, "openid profile", q.Get("scope"))
	return l
}

func TestClient_Exchange(t *testing.T) {
	f := openidtest.New(t, "tg-spam")
	c := newTestClient(t, f)

	t.Run("valid", func(t *testing.T) {
		f.SetClaims(map[string]any{"email": "a@example.com", "email_verified": "true", "roles": "admin"})
		l := authorize(t, f, c)
		claims, err := c.Exchange(t.Context(), openidtest.GoodCode, l)
		require.NoError(t, err)
		assert.Equal(t, Claims{Sub: "u1", Email: "a@example.com", EmailVerified: true, Roles: StringList{"admin"}}, claims)
	})
	t.Run("wrong code", func(t *testing.T) {
		l := authorize(t, f, c)
		_, err := c.Exchange(t.Context(), "bad", l)
		require.ErrorContains(t, err, "code exchange failed")
	})
	t.Run("wrong verifier", func(t *testing.T) {
		l := authorize(t, f, c)
		l.Verifier = NewLogin().Verifier
		_, err := c.Exchange(t.Context(), openidtest.GoodCode, l)
		require.ErrorContains(t, err, "code exchange failed")
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		l := authorize(t, f, c)
		f.SetNonce("other")
		_, err := c.Exchange(t.Context(), openidtest.GoodCode, l)
		require.ErrorContains(t, err, "nonce mismatch")
	})
	t.Run("no subject", func(t *testing.T) {
		f.SetClaims(map[string]any{"sub": ""})
		l := authorize(t, f, c)
		_, err := c.Exchange(t.Context(), openidtest.GoodCode, l)
		require.ErrorContains(t, err, "without a subject")
	})
	t.Run("token for another client", func(t *testing.T) {
		f.SetClaims(map[string]any{"aud": "other"})
		l := authorize(t, f, c)
		_, err := c.Exchange(t.Context(), openidtest.GoodCode, l)
		require.ErrorContains(t, err, "id token rejected")
	})
}

func TestClient_DiscoveryFailureIsCached(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New(Config{Issuer: srv.URL, ClientID: "c", ClientSecret: "s"})
	c.HTTP = srv.Client()

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, err := c.Discover(t.Context())
			assert.ErrorIs(t, err, ErrDiscovery)
		})
	}
	wg.Wait()
	mu.Lock()
	assert.Equal(t, 1, calls, "concurrent and repeated discoveries within the retry interval share one fetch")
	mu.Unlock()

	_, err := c.Exchange(t.Context(), "code", NewLogin())
	require.ErrorIs(t, err, ErrDiscovery, "exchange reports the discovery failure")

	c.mu.Lock()
	c.failedAt = time.Now().Add(-RetryAfter)
	c.mu.Unlock()
	_, err = c.Discover(t.Context())
	require.Error(t, err)
	mu.Lock()
	assert.Equal(t, 2, calls, "retried after the interval")
	mu.Unlock()
}

func TestClaims_Decode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Claims
	}{
		{"bool email_verified", `{"email_verified":true}`, Claims{EmailVerified: true}},
		{"string email_verified", `{"email_verified":"TRUE"}`, Claims{EmailVerified: true}},
		{"false string", `{"email_verified":"false"}`, Claims{}},
		{"number is false", `{"email_verified":1}`, Claims{}},
		{"role list", `{"roles":["a","b"]}`, Claims{Roles: StringList{"a", "b"}}},
		{"single group", `{"groups":"ops"}`, Claims{Groups: StringList{"ops"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c Claims
			require.NoError(t, json.Unmarshal([]byte(tc.in), &c))
			assert.Equal(t, tc.want, c)
		})
	}
	var c Claims
	require.Error(t, json.Unmarshal([]byte(`{"roles":[1]}`), &c))
}
