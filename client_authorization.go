package gocloak

import (
	"context"
	"github.com/pkg/errors"
	"net/http"
)

// ------------------
// Protection API
// ------------------

// GetResource returns a client's resource with the given id, using access token from admin
func (g *GoCloak) GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourceClient returns a client's resource with the given id, using access token from client
func (g *GoCloak) GetResourceClient(ctx context.Context, token, realm, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	// http://${host}:${port}/auth/realms/${realm_name}/authz/protection/resource_set/{resource_id}

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResources returns resources associated with the client, using access token from admin
func (g *GoCloak) GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcesClient returns resources associated with the client, using access token from client
func (g *GoCloak) GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	var resourceIDs []string
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&resourceIDs).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	for _, resourceID := range resourceIDs {
		resource, err := g.GetResourceClient(ctx, token, realm, resourceID)
		if err == nil {
			result = append(result, resource)
		}
	}

	return result, nil
}

// GetResourceServer returns resource server settings.
// The access token must have the realm view_clients role on its service
// account to be allowed to call this endpoint.
func (g *GoCloak) GetResourceServer(ctx context.Context, token, realm, idOfClient string) (*ResourceServerRepresentation, error) {
	const errMessage = "could not get resource server settings"

	var result *ResourceServerRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "settings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateResource updates a resource associated with the client, using access token from admin
func (g *GoCloak) UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateResourceClient updates a resource associated with the client, using access token from client
func (g *GoCloak) UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getRealmURL(realm, "authz", "protection", "resource_set", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// CreateResource creates a resource associated with the client, using access token from admin
func (g *GoCloak) CreateResource(ctx context.Context, token, realm string, idOfClient string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateResourceClient creates a resource associated with the client, using access token from client
func (g *GoCloak) CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteResource deletes a resource associated with the client (using an admin token)
func (g *GoCloak) DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourceClient deletes a resource associated with the client (using a client token)
func (g *GoCloak) DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	return checkForError(resp, err, errMessage)
}

// GetPolicy returns a client's policy with the given id
func (g *GoCloak) GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*PolicyRepresentation, error) {
	const errMessage = "could not get policy"

	var result PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPolicies returns policies associated with the client
func (g *GoCloak) GetPolicies(ctx context.Context, token, realm, idOfClient string, params GetPolicyParams) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	compResult, err := g.compareVersions("20.0.0", token, ctx)
	if err != nil {
		return nil, err
	}
	shouldAddType := compResult != 1

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}
	if !NilOrEmpty(params.Type) && shouldAddType {
		path = append(path, *params.Type)
	}

	var result []*PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePolicy creates a policy associated with the client
func (g *GoCloak) CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) (*PolicyRepresentation, error) {
	const errMessage = "could not create policy"

	if NilOrEmpty(policy.Type) {
		return nil, errors.New("type of a policy required")
	}

	compResult, err := g.compareVersions("20.0.0", token, ctx)
	if err != nil {
		return nil, err
	}
	shouldAddType := compResult != 1

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}

	if shouldAddType {
		path = append(path, *policy.Type)
	}

	var result PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(g.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePolicy updates a policy associated with the client
func (g *GoCloak) UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) error {
	const errMessage = "could not update policy"

	if NilOrEmpty(policy.ID) {
		return errors.New("ID of a policy required")
	}

	compResult, err := g.compareVersions("20.0.0", token, ctx)
	if err != nil {
		return err
	}
	shouldAddType := compResult != 1

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}

	if shouldAddType {
		path = append(path, *policy.Type)
	}

	path = append(path, *(policy.ID))

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(g.getAdminRealmURL(realm, path...))

	return checkForError(resp, err, errMessage)
}

// DeletePolicy deletes a policy associated with the client
func (g *GoCloak) DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error {
	const errMessage = "could not delete policy"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	return checkForError(resp, err, errMessage)
}

// GetAuthorizationPolicyAssociatedPolicies returns a client's associated policies of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyAssociatedPolicies(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policy associated policies"

	var result []*PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "associatedPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyResources returns a client's resources of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyResources(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyResourceRepresentation, error) {
	const errMessage = "could not get policy resources"

	var result []*PolicyResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyScopes returns a client's scopes of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyScopes(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyScopeRepresentation, error) {
	const errMessage = "could not get policy scopes"

	var result []*PolicyScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policy"

	var result ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		Get(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourcePolicies returns resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) GetResourcePolicies(ctx context.Context, token, realm string, params GetResourcePoliciesParams) ([]*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "uma-policy"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateResourcePolicy associates a permission with a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy ResourcePolicyRepresentation) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not create resource policy"

	var result ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(g.getRealmURL(realm, "authz", "protection", "uma-policy", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy ResourcePolicyRepresentation) error {
	const errMessage = "could not update resource policy"

	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetBody(policy).
		Put(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourcePolicy deletes a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error {
	const errMessage = "could not  delete resource policy"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// GetPermission returns a client's permission with the given id
func (g *GoCloak) GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDependentPermissions returns a client's permission with the given policy id
func (g *GoCloak) GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result []*PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "dependentPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionResources returns a client's resource attached for the given permission id
func (g *GoCloak) GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionResource, error) {
	const errMessage = "could not get permission resource"

	var result []*PermissionResource
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetScopePermissions returns permissions associated with the client scope
func (g *GoCloak) GetScopePermissions(ctx context.Context, token, realm, idOfClient, idOfScope string) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get scope permissions"

	var result []*PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", idOfScope, "permissions"))
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionScopes returns a client's scopes configured for the given permission id
func (g *GoCloak) GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionScope, error) {
	const errMessage = "could not get permission scopes"

	var result []*PermissionScope
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissions returns permissions associated with the client
func (g *GoCloak) GetPermissions(ctx context.Context, token, realm, idOfClient string, params GetPermissionParams) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "permission"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePermissionTicket creates a permission ticket, using access token from client
func (g *GoCloak) CreatePermissionTicket(ctx context.Context, token, realm string, permissions []CreatePermissionTicketParams) (*PermissionTicketResponseRepresentation, error) {
	const errMessage = "could not create permission ticket"

	err := checkPermissionTicketParams(permissions)
	if err != nil {
		return nil, err
	}

	var result PermissionTicketResponseRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permissions).
		Post(g.getRealmURL(realm, "authz", "protection", "permission"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GrantUserPermission lets resource owner grant permission for specific resource ID to specific user ID
func (g *GoCloak) GrantUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not grant user permission"

	err := checkPermissionGrantParams(permission)
	if err != nil {
		return nil, err
	}

	permission.Granted = BoolP(true)

	var result PermissionGrantResponseRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateUserPermission updates user permissions.
func (g *GoCloak) UpdateUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not update user permission"

	err := checkPermissionUpdateParams(permission)
	if err != nil {
		return nil, err
	}

	var result PermissionGrantResponseRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Put(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent { // permission updated to 'not granted' removes permission
		return nil, nil
	}

	return &result, nil
}

// GetUserPermissions gets granted permissions according query parameters
func (g *GoCloak) GetUserPermissions(ctx context.Context, token, realm string, params GetUserPermissionParams) ([]*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not get user permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*PermissionGrantResponseRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteUserPermission revokes permissions according query parameters
func (g *GoCloak) DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error {
	const errMessage = "could not delete user permission"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "permission", "ticket", ticketID))

	return checkForError(resp, err, errMessage)
}

// CreatePermission creates a permission associated with the client
func (g *GoCloak) CreatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) (*PermissionRepresentation, error) {
	const errMessage = "could not create permission"

	if NilOrEmpty(permission.Type) {
		return nil, errors.New("type of a permission required")
	}

	var result PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *(permission.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermission updates a permission associated with the client
func (g *GoCloak) UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) error {
	const errMessage = "could not update permission"

	if NilOrEmpty(permission.ID) {
		return errors.New("ID of a permission required")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(permission).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *permission.Type, *permission.ID))

	return checkForError(resp, err, errMessage)
}

// DeletePermission deletes a policy associated with the client
func (g *GoCloak) DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error {
	const errMessage = "could not delete permission"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	return checkForError(resp, err, errMessage)
}
