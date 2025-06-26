package gocloak

import (
	"context"
)

const apiPathMembers = "members"

// GetMemberOrganizations Gets all organizations for which a user has membership in
func (g *GoCloak) GetMemberOrganizations(ctx context.Context, token, realm, memberID string) ([]*OrganizationRepresentation, error) {
	const errMessage = "could not get member organizations"

	var result []*OrganizationRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(
			realm,
			apiPathOrganizations,
			apiPathMembers,
			memberID,
		))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetOrganizationMemberOrganizations Gets all organizations for which a user has membership in
func (g *GoCloak) GetOrganizationMemberOrganizations(ctx context.Context, token, realm, orgID, memberID string) ([]*OrganizationRepresentation, error) {
	const errMessage = "could not get member organizations"

	var result []*OrganizationRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(
			realm,
			apiPathOrganizations,
			orgID,
			apiPathMembers,
			memberID,
			apiPathOrganizations,
		))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddOrganizationMember Add user as a member to an organization
func (g *GoCloak) AddOrganizationMember(ctx context.Context, token, realm, orgID string, userID string) (string, error) {
	const errMessage = "could not create organization"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(userID).
		Post(g.getAdminRealmURL(
			realm,
			apiPathOrganizations,
			orgID,
			apiPathMembers,
		))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// RemoveOrganizationMember Delete a user's membership from an organization
func (g *GoCloak) RemoveOrganizationMember(ctx context.Context, token, realm, orgID, userID string) error {
	const errMessage = "could not delete member"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(
			realm,
			apiPathOrganizations,
			orgID,
			apiPathMembers,
			userID,
		))

	return checkForError(resp, err, errMessage)
}

// GetOrganizationMemberByID Get organization member by ID
func (g *GoCloak) GetOrganizationMemberByID(ctx context.Context, token, realm, orgID, userID string) (*MemberRepresentation, error) {
	const errMessage = "could not get member by id"

	var result *MemberRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(
			realm,
			apiPathOrganizations,
			orgID,
			apiPathMembers,
			userID,
		))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
