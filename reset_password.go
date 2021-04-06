package idx

import (
	"context"
	"fmt"
	"strings"
)

func (r *Response) InitPasswordRecovery(ctx context.Context, identifier string) (*Response, error) {
	resp, err := r.Identify(ctx, &IdentifyRequest{Identifier: identifier})
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticatorEnrollment == nil {
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' field is missing from the response")
	}
	return resp.CurrentAuthenticatorEnrollment.Value.Recover.Proceed(ctx, nil)
}

func (r *Response) SetPasswordOnReset(ctx context.Context, password string) (*Response, error) {
	ro, err := r.remediationOption("reset-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(password)))
	return ro.Proceed(ctx, credentials)
}
