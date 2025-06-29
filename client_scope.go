package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

// GetScope returns a client's scope with the given id
func (g *GoCloak) GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (*ScopeRepresentation, error) {
	const errMessage = "could not get scope"

	var result ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetScopes returns scopes associated with the client
func (g *GoCloak) GetScopes(ctx context.Context, token, realm, idOfClient string, params GetScopeParams) ([]*ScopeRepresentation, error) {
	const errMessage = "could not get scopes"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}
	var result []*ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateScope creates a scope associated with the client
func (g *GoCloak) CreateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (*ScopeRepresentation, error) {
	const errMessage = "could not create scope"

	var result ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(scope).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPermissionScope gets the permission scope associated with the client
func (g *GoCloak) GetPermissionScope(ctx context.Context, token, realm, idOfClient string, idOfScope string) (*PolicyRepresentation, error) {
	const errMessage = "could not get permission scope"

	var result PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", "scope", idOfScope))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermissionScope updates a permission scope associated with the client
func (g *GoCloak) UpdatePermissionScope(ctx context.Context, token, realm, idOfClient string, idOfScope string, policy PolicyRepresentation) error {
	const errMessage = "could not create permission scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", "scope", idOfScope))

	return checkForError(resp, err, errMessage)
}

// UpdateScope updates a scope associated with the client
func (g *GoCloak) UpdateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) error {
	const errMessage = "could not update scope"

	if NilOrEmpty(scope.ID) {
		return errors.New("ID of a scope required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", *(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteScope deletes a scope associated with the client
func (g *GoCloak) DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not delete scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	return checkForError(resp, err, errMessage)
}
