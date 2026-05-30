// Package uri builds safe http(s) URLs for outbound links (email actions).
package uri

import (
	"errors"
	"net/url"
)

var ErrInvalidURL = errors.New("invalid http(s) url")

// ActionLink sets the token query parameter on base. Base must be http or https with a host.
func ActionLink(base, token string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", ErrInvalidURL
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", ErrInvalidURL
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
