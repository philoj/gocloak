package gocloak

import "context"

// ClearRealmCache clears realm cache
func (g *GoCloak) ClearRealmCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear realm cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-realm-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearUserCache clears realm cache
func (g *GoCloak) ClearUserCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear user cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-user-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearKeysCache clears realm cache
func (g *GoCloak) ClearKeysCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear keys cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-keys-cache"))

	return checkForError(resp, err, errMessage)
}
