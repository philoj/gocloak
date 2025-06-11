package gocloak

import (
	"github.com/go-resty/resty/v2"
	"strings"
	"sync"
	"time"
)

// GoCloak provides functionalities to talk to Keycloak.
type GoCloak struct {
	basePath    string
	certsCache  sync.Map
	certsLock   sync.Mutex
	restyClient *resty.Client
	Config      struct {
		CertsInvalidateTime time.Duration
		authAdminRealms     string
		authRealms          string
		tokenEndpoint       string
		revokeEndpoint      string
		logoutEndpoint      string
		openIDConnect       string
		attackDetection     string
		version             string
	}
}

// Verify struct implements interface
var _ GoCloakIface = &GoCloak{}

// ===============
// Keycloak client
// ===============

// NewClient creates a new Client
func NewClient(basePath string, options ...func(*GoCloak)) *GoCloak {
	c := GoCloak{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		restyClient: resty.New(),
	}

	c.Config.CertsInvalidateTime = 10 * time.Minute
	c.Config.authAdminRealms = makeURL("admin", "realms")
	c.Config.authRealms = makeURL("realms")
	c.Config.tokenEndpoint = makeURL("protocol", "openid-connect", "token")
	c.Config.logoutEndpoint = makeURL("protocol", "openid-connect", "logout")
	c.Config.revokeEndpoint = makeURL("protocol", "openid-connect", "revoke")
	c.Config.openIDConnect = makeURL("protocol", "openid-connect")
	c.Config.attackDetection = makeURL("attack-detection", "brute-force")

	for _, option := range options {
		option(&c)
	}

	return &c
}
