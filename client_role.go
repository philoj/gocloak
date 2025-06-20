package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

// -----------
// Realm Roles
// -----------

// CreateRealmRole creates a role in a realm
func (g *GoCloak) CreateRealmRole(ctx context.Context, token string, realm string, role Role) (string, error) {
	const errMessage = "could not create realm role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(g.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetRealmRole returns a role from a realm by role's name
func (g *GoCloak) GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles", roleName))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoleByID returns a role from a realm by role's ID
func (g *GoCloak) GetRealmRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoles get all roles of the given realm.
func (g *GoCloak) GetRealmRoles(ctx context.Context, token, realm string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get realm roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByUserID returns all roles assigned to the given user
func (g *GoCloak) GetRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByGroupID returns all roles assigned to the given group
func (g *GoCloak) GetRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by group id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateRealmRole updates a role in a realm
func (g *GoCloak) UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(g.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// UpdateRealmRoleByID updates a role in a realm by role's ID
func (g *GoCloak) UpdateRealmRoleByID(ctx context.Context, token, realm, roleID string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(g.getAdminRealmURL(realm, "roles-by-id", roleID))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRole deletes a role in a realm by role's name
func (g *GoCloak) DeleteRealmRole(ctx context.Context, token, realm, roleName string) error {
	const errMessage = "could not delete realm role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToUser adds realm-level role mappings
func (g *GoCloak) AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not add realm role to user"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromUser deletes realm-level role mappings
func (g *GoCloak) DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not delete realm role from user"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleComposite adds a role to the composite.
func (g *GoCloak) AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not add realm role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleComposite deletes a role from the composite.
func (g *GoCloak) DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not delete realm role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetCompositeRealmRoles returns all realm composite roles associated with the given realm role
func (g *GoCloak) GetCompositeRealmRoles(ctx context.Context, token, realm, roleName string) ([]*Role, error) {
	const errMessage = "could not get composite realm roles by role"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles", roleName, "composites"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRolesByRoleID returns all realm composite roles associated with the given client role
func (g *GoCloak) GetCompositeRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
func (g *GoCloak) GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
func (g *GoCloak) GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
func (g *GoCloak) GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
func (g *GoCloak) GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
func (g *GoCloak) GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddClientRoleComposite adds roles as composite
func (g *GoCloak) AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not add client role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleComposite deletes composites from a role
func (g *GoCloak) DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not delete client role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// UpdateRole updates the given role.
func (g *GoCloak) UpdateRole(ctx context.Context, token, realm, idOfClient string, role Role) error {
	const errMessage = "could not update role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "roles", PString(role.Name)))

	return checkForError(resp, err, errMessage)
}

// GetRealmRoleGroups returns groups associated with the realm role
func (g *GoCloak) GetRealmRoleGroups(ctx context.Context, token, roleName, realm string) ([]*Group, error) {
	const errMessage = "could not get groups by realm roleName"

	var result []*Group
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles", roleName, "groups"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRoleMappingByGroupID gets the role mappings by group
func (g *GoCloak) GetRoleMappingByGroupID(ctx context.Context, token, realm, groupID string) (*MappingsRepresentation, error) {
	return g.getRoleMappings(ctx, token, realm, "groups", groupID)
}
