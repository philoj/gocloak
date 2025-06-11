package gocloak

import (
	"context"
	"fmt"
)

const organizationAPIPath = "organizations"

// CreateOrganization create an organization for a realm that has organizations enabled
func (g *GoCloak) CreateOrganization(ctx context.Context, token, realm string, org OrganizationRepresentation) (string, error) {
	const errMessage = "could not create organization"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(org).
		Post(g.getAdminRealmURL(realm, organizationAPIPath))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// DeleteOrganisation Delete organization by ID
func (g *GoCloak) DeleteOrganisation(ctx context.Context, token, realm, orgID string) error {
	const errMessage = "could not delete organization"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, organizationAPIPath, orgID))

	return checkForError(resp, err, errMessage)
}

// GetOrganizations Gets all organizations for a realm. If organizations are not enabled for the realm, returns 404
func (g *GoCloak) GetOrganizations(ctx context.Context, token, realm string, params GetOrganizationsParams) ([]*OrganizationRepresentation, error) {
	const errMessage = "could not get organizations"

	var result []*OrganizationRepresentation
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errMessage, err)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, organizationAPIPath))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetOrganizationByID Get organization by ID
func (g *GoCloak) GetOrganizationByID(ctx context.Context, token, realm string, orgID string) (*OrganizationRepresentation, error) {
	const errMessage = "could not get organization by id"

	var result *OrganizationRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, organizationAPIPath, orgID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
