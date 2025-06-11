package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

// CreateGroup creates a new group.
func (g *GoCloak) CreateGroup(ctx context.Context, token, realm string, group Group) (string, error) {
	const errMessage = "could not create group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// CreateChildGroup creates a new child group
func (g *GoCloak) CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error) {
	const errMessage = "could not create child group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateGroup updates the given group.
func (g *GoCloak) UpdateGroup(ctx context.Context, token, realm string, updatedGroup Group) error {
	const errMessage = "could not update group"

	if NilOrEmpty(updatedGroup.ID) {
		return errors.Wrap(errors.New("ID of a group required"), errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(updatedGroup).
		Put(g.getAdminRealmURL(realm, "groups", PString(updatedGroup.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateGroupManagementPermissions updates the given group management permissions
func (g *GoCloak) UpdateGroupManagementPermissions(ctx context.Context, accessToken, realm string, idOfGroup string, managementPermissions ManagementPermissionRepresentation) (*ManagementPermissionRepresentation, error) {
	const errMessage = "could not update group management permissions"

	var result ManagementPermissionRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		SetBody(managementPermissions).
		Put(g.getAdminRealmURL(realm, "groups", idOfGroup, "management", "permissions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteGroup deletes the group with the given groupID.
func (g *GoCloak) DeleteGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not delete group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetDefaultGroups returns a list of default groups
func (g *GoCloak) GetDefaultGroups(ctx context.Context, token, realm string) ([]*Group, error) {
	const errMessage = "could not get default groups"

	var result []*Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "default-groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultGroup adds group to the list of default groups
func (g *GoCloak) AddDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not add default group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Put(g.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultGroup removes group from the list of default groups
func (g *GoCloak) RemoveDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not remove default group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetGroup get group with id in realm
func (g *GoCloak) GetGroup(ctx context.Context, token, realm, groupID string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetChildGroups get child groups of group with id in realm
func (g *GoCloak) GetChildGroups(ctx context.Context, token, realm, groupID string, params GetChildGroupsParams) ([]*Group, error) {
	const errMessage = "could not get child groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupByPath get group with path in realm
func (g *GoCloak) GetGroupByPath(ctx context.Context, token, realm, groupPath string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "group-by-path", groupPath))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroups get all groups in realm
func (g *GoCloak) GetGroups(ctx context.Context, token, realm string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupManagementPermissions returns whether group Authorization permissions have been initialized or not and a reference
// to the managed permissions
func (g *GoCloak) GetGroupManagementPermissions(ctx context.Context, token, realm string, idOfGroup string) (*ManagementPermissionRepresentation, error) {
	const errMessage = "could not get management permissions"

	var result ManagementPermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", idOfGroup, "management", "permissions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroupsByRole gets groups assigned with a specific role of a realm
func (g *GoCloak) GetGroupsByRole(ctx context.Context, token, realm string, roleName string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsByClientRole gets groups with specified roles assigned of given client within a realm
func (g *GoCloak) GetGroupsByClientRole(ctx context.Context, token, realm string, roleName string, clientID string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsCount gets the groups count in the realm
func (g *GoCloak) GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error) {
	const errMessage = "could not get groups count"

	var result GroupsCount
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result.Count, nil
}

// GetGroupMembers get a list of users of group with id in realm
func (g *GoCloak) GetGroupMembers(ctx context.Context, token, realm, groupID string, params GetGroupsParams) ([]*User, error) {
	const errMessage = "could not get group members"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "members"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddRealmRoleToGroup adds realm-level role mappings
func (g *GoCloak) AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not add realm role to group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromGroup deletes realm-level role mappings
func (g *GoCloak) DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not delete realm role from group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// GetUserGroups get all groups for user
func (g *GoCloak) GetUserGroups(ctx context.Context, token, realm, userID string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get user groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "users", userID, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddUserToGroup puts given user to given group
func (g *GoCloak) AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not add user to group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Put(g.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFromGroup deletes given user from given group
func (g *GoCloak) DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not delete user from group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// AddClientRolesToGroup adds a client role to the group
func (g *GoCloak) AddClientRolesToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not add client role to group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToGroup adds a client role to the group
//
// Deprecated: replaced by AddClientRolesToGroup
func (g *GoCloak) AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	return g.AddClientRolesToGroup(ctx, token, realm, idOfClient, groupID, roles)
}

// DeleteClientRoleFromGroup removes a client role from from the group
func (g *GoCloak) DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not client role from group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}
