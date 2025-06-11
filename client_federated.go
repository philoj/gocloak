package gocloak

import "context"

// GetUserFederatedIdentities gets all user federated identities
func (g *GoCloak) GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error) {
	const errMessage = "could not get user federated identities"

	var res []*FederatedIdentityRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(g.getAdminRealmURL(realm, "users", userID, "federated-identity"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, err
}

// CreateUserFederatedIdentity creates an user federated identity
func (g *GoCloak) CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error {
	const errMessage = "could not create user federeated identity"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(federatedIdentityRep).
		Post(g.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFederatedIdentity deletes an user federated identity
func (g *GoCloak) DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error {
	const errMessage = "could not delete user federeated identity"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}
