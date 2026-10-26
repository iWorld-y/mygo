package mygo

import "github.com/egoist/mygo/internal/platform"

// AuthenticationRequest describes an HTTP authentication challenge of a
// page: the sign-in a site behind Basic or Digest authentication asks for.
type AuthenticationRequest struct {
	// Scheme is the method of the challenge, "HTTPBasic" or "HTTPDigest".
	Scheme string
	// Realm is the space to sign in to, named by the server, such as
	// "Luker".
	Realm string
	// Host is the host the challenge comes from, such as "example.com".
	Host string
}

// Credential answers an AuthenticationRequest.
type Credential struct {
	Username string
	Password string
}

// SetAuthenticationHandler answers the HTTP authentication challenges of
// the window's pages with credentials the app keeps. fn runs on the main
// thread; returning nil leaves the challenge to the web view, which shows
// the sign-in dialog it shows in its own browser. nil restores that default.
//
// A page cannot see the password: the web view sends it in the request's
// Authorization header, as it does one the user types into the dialog.
func (p *Page) SetAuthenticationHandler(fn func(req AuthenticationRequest) *Credential) {
	p.w.mu.Lock()
	p.w.authHandler = fn
	p.w.mu.Unlock()
}

// HasAuthenticationHandler reports whether the window answers challenges.
func (h *windowHandler) HasAuthenticationHandler() bool {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	return h.w.authHandler != nil
}

func (h *windowHandler) AuthenticationRequested(ch platform.AuthChallenge) (platform.Credential, bool) {
	h.w.mu.Lock()
	fn := h.w.authHandler
	h.w.mu.Unlock()
	if fn == nil {
		return platform.Credential{}, false
	}
	req := AuthenticationRequest{Scheme: ch.Scheme, Realm: ch.Realm, Host: ch.Host}
	if c := fn(req); c != nil {
		return platform.Credential{Username: c.Username, Password: c.Password}, true
	}
	return platform.Credential{}, false
}
