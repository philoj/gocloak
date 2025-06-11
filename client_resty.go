package gocloak

import "github.com/go-resty/resty/v2"

// RestyClient returns the internal resty g.
// This can be used to configure the g.
func (g *GoCloak) RestyClient() *resty.Client {
	return g.restyClient
}

// SetRestyClient overwrites the internal resty g.
func (g *GoCloak) SetRestyClient(restyClient *resty.Client) {
	g.restyClient = restyClient
}
