package gocloak

import "context"

// GetAuthenticationFlows get all authentication flows from a realm
func (g *GoCloak) GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAuthenticationFlow get an authentication flow with the given ID
func (g *GoCloak) GetAuthenticationFlow(ctx context.Context, token, realm string, authenticationFlowID string) (*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationFlow creates a new Authentication flow in a realm
func (g *GoCloak) CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) error {
	const errMessage = "could not create authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows"))

	return checkForError(resp, err, errMessage)
}

// UpdateAuthenticationFlow a given Authentication Flow
func (g *GoCloak) UpdateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation, authenticationFlowID string) (*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not create authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteAuthenticationFlow deletes a flow in a realm with the given ID
func (g *GoCloak) DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error {
	const errMessage = "could not delete authentication flows"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "flows", flowID))

	return checkForError(resp, err, errMessage)
}

// GetAuthenticationExecutions retrieves all executions of a given flow
func (g *GoCloak) GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) ([]*ModifyAuthenticationExecutionRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*ModifyAuthenticationExecutionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
func (g *GoCloak) CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution CreateAuthenticationExecutionRepresentation) error {
	const errMessage = "could not create authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "execution"))

	return checkForError(resp, err, errMessage)
}

// UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
func (g *GoCloak) UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution ModifyAuthenticationExecutionRepresentation) error {
	const errMessage = "could not update authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	return checkForError(resp, err, errMessage)
}

// DeleteAuthenticationExecution delete a single execution with the given ID
func (g *GoCloak) DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) error {
	const errMessage = "could not delete authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "executions", executionID))

	return checkForError(resp, err, errMessage)
}

// CreateAuthenticationExecutionFlow creates a new execution for the given flow name in the given realm
func (g *GoCloak) CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, executionFlow CreateAuthenticationExecutionFlowRepresentation) error {
	const errMessage = "could not create authentication execution flow"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(executionFlow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "flow"))

	return checkForError(resp, err, errMessage)
}
