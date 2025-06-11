package gocloak

import (
	"context"
	"fmt"
)

// GetOrganisations Gets all organisations for a realm. If organisations are not enabled for the realm, returns 404
func (g *GoCloak) GetOrganisations(ctx context.Context, token, realm string, params GetOrganisationsParams) ([]*OrganizationRepresentation, error) {
	const errMessage = "could not get organisations" // TODO verify message

	var result []*OrganizationRepresentation
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errMessage, err)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "organizations"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
