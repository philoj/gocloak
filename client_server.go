package gocloak

import "context"

// GetServerInfo fetches the server info.
func (g *GoCloak) GetServerInfo(ctx context.Context, accessToken string) (*ServerInfoRepresentation, error) {
	errMessage := "could not get server info"
	var result *ServerInfoRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(makeURL(g.basePath, "admin", "serverinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetKeyStoreConfig get keystoreconfig of the realm
func (g *GoCloak) GetKeyStoreConfig(ctx context.Context, token, realm string) (*KeyStoreConfig, error) {
	const errMessage = "could not get key store config"

	var result KeyStoreConfig
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "keys"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}
