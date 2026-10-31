// Package openid is the OpenID Connect client shared by the web UI login and the join captcha: lazy discovery,
// the authorization code flow with PKCE, and id token verification
package openid

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrDiscovery wraps a failure to reach or read the issuer's metadata
var ErrDiscovery = errors.New("oidc discovery failed")

// WriteTimeout covers the provider round trips of a login (discovery, code exchange, jwks), longer than the
// write timeouts of the servers handling logins
const WriteTimeout = 45 * time.Second

// RetryAfter is how long a failed discovery is returned without a new fetch
const RetryAfter = 5 * time.Second

// Config of a client registered at the issuer
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string // openid is always asked for
}

// Client talks to one issuer. Discovery runs on first use and is kept, so the caller starts even while the
// issuer is unreachable
type Client struct {
	HTTP *http.Client // replaceable in tests

	cfg      Config
	fetchMu  sync.Mutex // serializes discovery, so waiters share one fetch instead of each starting one
	mu       sync.Mutex // guards the fields below
	provider *Provider
	failedAt time.Time // last failed discovery, see RetryAfter
	failErr  error
}

// Provider is what discovery yields
type Provider struct {
	EndSession string // end_session_endpoint, empty when the issuer has none
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
}

// Login is the per-login secret state carried from the authorization redirect to the callback
type Login struct {
	State    string
	Nonce    string
	Verifier string
}

// NewLogin makes a fresh login state
func NewLogin() Login {
	return Login{State: rand.Text(), Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier()}
}

// New makes a client, nothing is fetched yet
func New(cfg Config) *Client {
	return &Client{cfg: cfg, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// Discover fetches the provider metadata on first use and keeps it. One fetch runs at a time and others wait for
// its result; a failure is returned without a new fetch for RetryAfter, so a down issuer costs one outbound
// request per interval
func (c *Client) Discover(ctx context.Context) (*Provider, error) {
	if p, err, ok := c.known(); ok {
		return p, err
	}
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	if p, err, ok := c.known(); ok { // fetched or failed while this request waited
		return p, err
	}
	// detached from the request: a client that goes away must not fail, and cache the failure of, the fetch
	// other requests wait on. c.HTTP carries the timeout
	p, err := c.fetchProvider(context.WithoutCancel(ctx))
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.failedAt, c.failErr = time.Now(), err
		return nil, err
	}
	c.provider = p
	return p, nil
}

// known returns the discovered provider, or the recent discovery failure, and whether either is set
func (c *Client) known() (*Provider, error, bool) { //nolint:revive // the bool says whether to fetch
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil, true
	}
	if c.failErr != nil && time.Since(c.failedAt) < RetryAfter {
		return nil, c.failErr, true
	}
	return nil, nil, false
}

// fetchProvider runs the discovery request and builds the client config from it
func (c *Client) fetchProvider(ctx context.Context) (*Provider, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, c.HTTP), c.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("%w: can't read provider metadata: %w", ErrDiscovery, err)
	}
	return &Provider{
		EndSession: meta.EndSession,
		verifier:   provider.Verifier(&oidc.Config{ClientID: c.cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     c.cfg.ClientID,
			ClientSecret: c.cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  c.cfg.RedirectURL,
			Scopes:       append([]string{oidc.ScopeOpenID}, c.cfg.Scopes...),
		},
	}, nil
}

// AuthCodeURL is the issuer's authorization url for a login, with the nonce and the PKCE S256 challenge
func (p *Provider) AuthCodeURL(l Login) string {
	return p.oauth.AuthCodeURL(l.State, oidc.Nonce(l.Nonce), oauth2.S256ChallengeOption(l.Verifier))
}

// Exchange trades the callback code for tokens and returns the claims of the verified id token whose nonce
// matches the login. The caller checks the state before
func (c *Client) Exchange(ctx context.Context, code string, l Login) (Claims, error) {
	p, err := c.Discover(ctx)
	if err != nil {
		return Claims{}, err
	}
	ctx = oidc.ClientContext(ctx, c.HTTP)
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(l.Verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("oidc code exchange failed: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return Claims{}, errors.New("no id token")
	}
	idToken, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc id token rejected: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(l.Nonce)) != 1 {
		return Claims{}, errors.New("oidc id token rejected: nonce mismatch")
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return Claims{}, fmt.Errorf("can't decode oidc id token claims: %w", err)
	}
	if claims.Sub == "" {
		return Claims{}, errors.New("oidc id token without a subject")
	}
	return claims, nil
}

// Claims are the id token claims callers match accounts against
type Claims struct {
	Sub           string     `json:"sub"`
	Email         string     `json:"email"`
	EmailVerified FlexBool   `json:"email_verified"`
	Username      string     `json:"preferred_username"`
	Roles         StringList `json:"roles"`
	Groups        StringList `json:"groups"`
}

// FlexBool decodes a JSON bool or the strings "true"/"false", as some providers send email_verified
type FlexBool bool

// UnmarshalJSON implements json.Unmarshaler
func (b *FlexBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("can't decode bool claim: %w", err)
	}
	switch t := v.(type) {
	case bool:
		*b = FlexBool(t)
	case string:
		*b = FlexBool(strings.EqualFold(t, "true"))
	default:
		*b = false
	}
	return nil
}

// StringList decodes a JSON array of strings or a single string, as some providers send a lone role or group
type StringList []string

// UnmarshalJSON implements json.Unmarshaler
func (l *StringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*l = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("can't decode list claim: %w", err)
	}
	*l = many
	return nil
}

// ExtendWriteDeadline lifts the server's write timeout to WriteTimeout for a handler that waits on the provider
func ExtendWriteDeadline(w http.ResponseWriter) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		log.Printf("[WARN] can't extend write deadline: %v", err)
	}
}
