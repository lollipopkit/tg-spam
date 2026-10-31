// Package openidtest provides a minimal OpenID Connect issuer for tests
package openidtest

import (
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
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// GoodCode is the only authorization code the token endpoint accepts
const GoodCode = "good-code"

// Issuer serves discovery, jwks and a token endpoint that checks the PKCE verifier. Its tokens are issued for
// ClientID with sub "u1" unless Claims say otherwise
type Issuer struct {
	Srv      *httptest.Server
	ClientID string

	mu        sync.Mutex
	key       *rsa.PrivateKey
	challenge string
	nonce     string
	claims    map[string]any
	noLogout  bool
}

// New starts an issuer for clientID, closed when the test ends
func New(t testing.TB, clientID string) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &Issuer{key: key, ClientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		meta := map[string]any{
			"issuer":                                f.Srv.URL,
			"authorization_endpoint":                f.Srv.URL + "/authorize",
			"token_endpoint":                        f.Srv.URL + "/token",
			"jwks_uri":                              f.Srv.URL + "/jwks",
			"end_session_endpoint":                  f.Srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		f.mu.Lock()
		if f.noLogout {
			delete(meta, "end_session_endpoint")
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(meta)
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
		if r.PostForm.Get("code") != GoodCode || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{"iss": f.Srv.URL, "aud": f.ClientID, "sub": "u1", "nonce": f.nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
		maps.Copy(claims, f.claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer",
			"id_token": f.sign(t, claims)})
	})
	f.Srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.Srv.Close)
	return f
}

// Authorize records the PKCE challenge and nonce of an authorization url, as the user's visit to it would
func (f *Issuer) Authorize(t testing.TB, authURL string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, f.Srv.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
	q := u.Query()
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	f.mu.Lock()
	f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	f.mu.Unlock()
	return q
}

// SetClaims sets extra id token claims, overriding the defaults
func (f *Issuer) SetClaims(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = claims
}

// SetNonce overrides the nonce put into the next id token
func (f *Issuer) SetNonce(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = nonce
}

// Pending returns the PKCE challenge and nonce of the last authorization
func (f *Issuer) Pending() (challenge, nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenge, f.nonce
}

// SetPending restores what Pending returned, to finish an earlier authorization
func (f *Issuer) SetPending(challenge, nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenge, f.nonce = challenge, nonce
}

// SetNoLogout drops end_session_endpoint from discovery
func (f *Issuer) SetNoLogout() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noLogout = true
}

func (f *Issuer) sign(t testing.TB, claims map[string]any) string {
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
