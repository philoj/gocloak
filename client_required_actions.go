package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

// GetRequiredActions gets a list of required actions for a given realm
func (g *GoCloak) GetRequiredActions(ctx context.Context, token string, realm string) ([]*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required actions"
	var result []*RequiredActionProviderRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "required-actions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, err
}

// GetRequiredAction gets a required action for a given realm
func (g *GoCloak) GetRequiredAction(ctx context.Context, token string, realm string, alias string) (*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required action"
	var result RequiredActionProviderRepresentation

	if alias == "" {
		return nil, errors.New("alias is required for getting a required action")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, err
}

// UpdateRequiredAction updates a required action for a given realm
func (g *GoCloak) UpdateRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not update required action"

	if NilOrEmpty(requiredAction.ProviderID) {
		return errors.New("providerId is required for updating a required action")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Put(g.getAdminRealmURL(realm, "authentication", "required-actions", *requiredAction.ProviderID))

	return checkForError(resp, err, errMessage)
}

// DeleteRequiredAction updates a required action for a given realm
func (g *GoCloak) DeleteRequiredAction(ctx context.Context, token string, realm string, alias string) error {
	const errMessage = "could not delete required action"

	if alias == "" {
		return errors.New("alias is required for deleting a required action")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// RegisterRequiredAction creates a required action for a given realm
func (g *GoCloak) RegisterRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not create required action"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Post(g.getAdminRealmURL(realm, "authentication", "register-required-action"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// GetUnregisteredRequiredActions gets a list of unregistered required actions for a given realm
func (g *GoCloak) GetUnregisteredRequiredActions(ctx context.Context, token string, realm string) ([]*UnregisteredRequiredActionProviderRepresentation, error) {
	const errMessage = "could not get unregistered required actions"

	var result []*UnregisteredRequiredActionProviderRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "unregistered-required-actions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
