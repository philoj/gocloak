package gocloak

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"strings"
)

func getID(resp *resty.Response) string {
	header := resp.Header().Get("Location")
	splittedPath := strings.Split(header, urlSeparator)

	return splittedPath[len(splittedPath)-1]
}

func findUsedKey(usedKeyID string, keys []CertResponseKey) *CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == usedKeyID {
			return &key
		}
	}

	return nil
}

func injectTracingHeaders(ctx context.Context, req *resty.Request) *resty.Request {
	// look for span in context, do nothing if span is not found
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return req
	}

	// look for tracer in context, use global tracer if not found
	tracer, ok := ctx.Value(tracerContextKey).(opentracing.Tracer)
	if !ok || tracer == nil {
		tracer = opentracing.GlobalTracer()
	}

	// inject tracing header into request
	err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))
	if err != nil {
		return req
	}

	return req
}

func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
			Type:    ParseAPIErrType(err),
		}
	}

	if resp == nil {
		return &APIError{
			Message: "empty response",
			Type:    ParseAPIErrType(err),
		}
	}

	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &APIError{
			Code:    resp.StatusCode(),
			Message: msg,
			Type:    ParseAPIErrType(err),
		}
	}

	return nil
}

// UserAttributeContains checks if the given attribute value is set
func UserAttributeContains(attributes map[string][]string, attribute, value string) bool {
	for _, item := range attributes[attribute] {
		if item == value {
			return true
		}
	}
	return false
}

// checkPermissionTicketParams checks that mandatory fields are present
func checkPermissionTicketParams(permissions []CreatePermissionTicketParams) error {
	if len(permissions) == 0 {
		return errors.New("at least one permission ticket must be requested")
	}

	for _, pt := range permissions {

		if NilOrEmpty(pt.ResourceID) {
			return errors.New("resourceID required for permission ticket")
		}
		if NilOrEmptyArray(pt.ResourceScopes) {
			return errors.New("at least one resourceScope required for permission ticket")
		}
	}

	return nil
}

// checkPermissionGrantParams checks for mandatory fields
func checkPermissionGrantParams(permission PermissionGrantParams) error {
	if NilOrEmpty(permission.RequesterID) {
		return errors.New("requesterID required to grant user permission")
	}
	if NilOrEmpty(permission.ResourceID) {
		return errors.New("resourceID required to grant user permission")
	}
	if NilOrEmpty(permission.ScopeName) {
		return errors.New("scopeName required to grant user permission")
	}

	return nil
}

// checkPermissionUpdateParams
func checkPermissionUpdateParams(permission PermissionGrantParams) error {
	err := checkPermissionGrantParams(permission)
	if err != nil {
		return err
	}

	if permission.Granted == nil {
		return errors.New("granted required to update user permission")
	}
	return nil
}

const urlSeparator string = "/"

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}
