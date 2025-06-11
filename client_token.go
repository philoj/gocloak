package gocloak

import (
	"context"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

// RetrospectToken calls the openid-connect introspect endpoint
func (g *GoCloak) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*IntroSpectTokenResult, error) {
	const errMessage = "could not introspect requesting party token"

	var result IntroSpectTokenResult
	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"token_type_hint": "requesting_party_token",
			"token":           accessToken,
		}).
		SetResult(&result).
		Post(g.getRealmURL(realm, g.Config.tokenEndpoint, "introspect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DecodeAccessToken decodes the accessToken
func (g *GoCloak) DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
	if err != nil {
		return nil, nil, err
	}
	return token, &claims, nil
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (g *GoCloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	return g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
}

// GetToken uses TokenOptions to fetch a token.
func (g *GoCloak) GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error) {
	const errMessage = "could not get token"

	var token JWT
	var req *resty.Request

	if !NilOrEmpty(options.ClientSecret) {
		req = g.GetRequestWithBasicAuth(ctx, *options.ClientID, *options.ClientSecret)
	} else {
		req = g.GetRequest(ctx)
	}

	resp, err := req.SetFormData(options.FormData()).
		SetResult(&token).
		Post(g.getRealmURL(realm, g.Config.tokenEndpoint))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &token, nil
}

// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
func (g *GoCloak) GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error) {
	const errMessage = "could not get requesting party token"

	var res JWT

	resp, err := g.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissions returns a requesting party permissions granted by the server
func (g *GoCloak) GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error) {
	const errMessage = "could not get requesting party token"

	var res []RequestingPartyPermission

	options.ResponseMode = StringP("permissions")

	resp, err := g.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetRequestingPartyPermissionDecision returns a requesting party permission decision granted by the server
func (g *GoCloak) GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*RequestingPartyPermissionDecision, error) {
	const errMessage = "could not get requesting party token"

	var res RequestingPartyPermissionDecision

	options.ResponseMode = StringP("decision")

	resp, err := g.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// RefreshToken refreshes the given token.
// May return a *APIError with further details about the issue.
func (g *GoCloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}

// RevokeToken revokes the passed token. The token can either be an access or refresh token.
func (g *GoCloak) RevokeToken(ctx context.Context, realm, clientID, clientSecret, refreshToken string) error {
	const errMessage = "could not revoke token"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"token":         refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.revokeEndpoint))

	return checkForError(resp, err, errMessage)
}

// GetIssuer gets the issuer of the given realm
func (g *GoCloak) GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}
