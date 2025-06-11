package gocloak

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/philoj/gocloak/v13/pkg/jwx"
	"github.com/pkg/errors"
	"golang.org/x/mod/semver"
	"net/url"
	"strings"
)

// Compares the provided version against the current version of the Keycloak server.
// Current version is fetched from the serverinfo if not already set.
//
// Returns:
//
// -1 if the provided version is lower than the server version
//
// 0 if the provided version is equal to the server version
//
// 1 if the provided version is higher than the server version
func (g *GoCloak) compareVersions(v, token string, ctx context.Context) (int, error) {
	curVersion := g.Config.version
	if curVersion == "" {
		curV, err := g.getServerVersion(ctx, token)
		if err != nil {
			return 0, err
		}

		curVersion = curV
	}

	curVersion = "v" + g.Config.version
	if v[0] != 'v' {
		v = "v" + v
	}

	return semver.Compare(curVersion, v), nil
}

// Get the server version from the serverinfo endpoint.
// If the version is already set, it will return the cached version.
// Otherwise, it will fetch the version from the serverinfo endpoint and cache it.
func (g *GoCloak) getServerVersion(ctx context.Context, token string) (string, error) {
	if g.Config.version != "" {
		return g.Config.version, nil
	}

	serverInfo, err := g.GetServerInfo(ctx, token)
	if err != nil {
		return "", err
	}

	g.Config.version = *(serverInfo.SystemInfo.Version)

	return g.Config.version, nil
}

func (g *GoCloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

func (g *GoCloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authAdminRealms, realm}, path...)
	return makeURL(path...)
}

func (g *GoCloak) getAttackDetectionURL(realm string, user string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authAdminRealms, realm, g.Config.attackDetection, user}, path...)
	return makeURL(path...)
}

func (g *GoCloak) getNewCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (g *GoCloak) decodeAccessTokenWithClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	const errMessage = "could not decode access token"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	certResult, err := g.GetCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	if strings.HasPrefix(decodedHeader.Alg, "ES") {
		return jwx.DecodeAccessTokenECDSACustomClaims(accessToken, usedKey.X, usedKey.Y, usedKey.Crv, claims)
	} else if strings.HasPrefix(decodedHeader.Alg, "RS") {
		return jwx.DecodeAccessTokenRSACustomClaims(accessToken, usedKey.E, usedKey.N, claims)
	}
	return nil, fmt.Errorf("unsupported algorithm")
}

func (g *GoCloak) getRoleMappings(ctx context.Context, token, realm, path, objectID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get role mappings"

	var result MappingsRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, path, objectID, "role-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (g *GoCloak) getRequestingParty(ctx context.Context, token string, realm string, options RequestingPartyTokenOptions, res interface{}) (*resty.Response, error) {
	return g.GetRequestWithBearerAuth(ctx, token).
		SetFormData(options.FormData()).
		SetFormDataFromValues(url.Values{"permission": PStringSlice(options.Permissions)}).
		SetResult(&res).
		Post(g.getRealmURL(realm, g.Config.tokenEndpoint))
}
