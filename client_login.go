package gocloak

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/philoj/gocloak/v13/pkg/jwx"
	"github.com/segmentio/ksuid"
)

const (
	adminClientID string = "admin-cli"
)

// LoginAdmin performs a login with Admin client
func (g *GoCloak) LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}

// LoginClient performs a login with client credentials
func (g *GoCloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string, scopes ...string) (*JWT, error) {
	opts := TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	}

	if len(scopes) > 0 {
		opts.Scope = &scopes[0]
	}

	return g.GetToken(ctx, realm, opts)
}

// LoginClientTokenExchange will exchange the presented token for a user's token
// Requires Token-Exchange is enabled: https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange
func (g *GoCloak) LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (*JWT, error) {
	tokenOptions := TokenOptions{
		ClientID:           &clientID,
		ClientSecret:       &clientSecret,
		GrantType:          StringP("urn:ietf:params:oauth:grant-type:token-exchange"),
		SubjectToken:       &token,
		RequestedTokenType: StringP("urn:ietf:params:oauth:token-type:refresh_token"),
		Audience:           &targetClient,
	}
	if userID != "" {
		tokenOptions.RequestedSubject = &userID
	}
	return g.GetToken(ctx, realm, tokenOptions)
}

// DirectNakedImpersonationTokenExchange performs "Direct Naked Impersonation"
// See: https://www.keycloak.org/docs/latest/securing_apps/index.html#direct-naked-impersonation
func (g *GoCloak) DirectNakedImpersonationTokenExchange(ctx context.Context, clientID, clientSecret, realm, userID string) (*JWT, error) {
	tokenOptions := TokenOptions{
		ClientID:           &clientID,
		ClientSecret:       &clientSecret,
		GrantType:          StringP("urn:ietf:params:oauth:grant-type:token-exchange"),
		RequestedTokenType: StringP("urn:ietf:params:oauth:token-type:refresh_token"),
		RequestedSubject:   StringP(userID),
	}
	return g.GetToken(ctx, realm, tokenOptions)
}

// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
func (g *GoCloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.NumericDate,
) (*JWT, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: expiresAt,
		Issuer:    clientID,
		Subject:   clientID,
		ID:        ksuid.New().String(),
		Audience: jwt.ClaimStrings{
			g.getRealmURL(realm),
		},
	}
	assertion, err := jwx.SignClaims(claims, key, signedMethod)
	if err != nil {
		return nil, err
	}

	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (g *GoCloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Scope:        StringP("openid"),
	})
}

// LoginOtp performs a login with user credentials and otp token
func (g *GoCloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Totp:         &totp,
	})
}
