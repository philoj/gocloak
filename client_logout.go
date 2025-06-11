package gocloak

import "context"

// Logout logs out users with refresh token
func (g *GoCloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutPublicClient performs a logout using a public client and the accessToken.
func (g *GoCloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error {
	const errMessage = "could not logout public client"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutAllSessions logs out all sessions of a user given an id.
func (g *GoCloak) LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Post(g.getAdminRealmURL(realm, "users", userID, "logout"))

	return checkForError(resp, err, errMessage)
}

// RevokeUserConsents revokes the given user consent.
func (g *GoCloak) RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error {
	const errMessage = "could not revoke consents"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Delete(g.getAdminRealmURL(realm, "users", userID, "consents", clientID))

	return checkForError(resp, err, errMessage)
}

// LogoutUserSession logs out a single sessions of a user given a session id
func (g *GoCloak) LogoutUserSession(ctx context.Context, accessToken, realm, session string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Delete(g.getAdminRealmURL(realm, "sessions", session))

	return checkForError(resp, err, errMessage)
}
