package gocloak

import "time"

// ==== Functional Options ===

// SetLegacyWildFlySupport maintain legacy WildFly support.
func SetLegacyWildFlySupport() func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.authAdminRealms = makeURL("auth", "admin", "realms")
		g.Config.authRealms = makeURL("auth", "realms")
	}
}

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.authRealms = url
	}
}

// SetAuthAdminRealms sets the auth admin realm
func SetAuthAdminRealms(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.authAdminRealms = url
	}
}

// SetTokenEndpoint sets the token endpoint
func SetTokenEndpoint(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.tokenEndpoint = url
	}
}

// SetRevokeEndpoint sets the revoke endpoint
func SetRevokeEndpoint(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.revokeEndpoint = url
	}
}

// SetLogoutEndpoint sets the logout
func SetLogoutEndpoint(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.logoutEndpoint = url
	}
}

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.openIDConnect = url
	}
}

// SetCertCacheInvalidationTime sets the logout
func SetCertCacheInvalidationTime(duration time.Duration) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.CertsInvalidateTime = duration
	}
}
