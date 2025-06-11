package gocloak

import (
	"context"
	"github.com/pkg/errors"
	"time"
)

// GetUserInfo calls the UserInfo endpoint
func (g *GoCloak) GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (g *GoCloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (g *GoCloak) GetCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := g.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	g.certsLock.Lock()
	defer g.certsLock.Unlock()

	if cert, ok := g.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	cert, err := g.getNewCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	g.certsCache.Store(realm, cert)
	time.AfterFunc(g.Config.CertsInvalidateTime, func() {
		g.certsCache.Delete(realm)
	})

	return cert, nil
}
