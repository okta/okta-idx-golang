package idx

import (
	"context"
	"fmt"
	"strings"
)

type EmailResponse struct {
	resp *Response
}

func (r *Response) SendEnrollmentEmailVerificationCode(ctx context.Context) (*EmailResponse, error) {
	ro, authID, err := r.authenticatorOption("select-authenticator-enroll", "Email")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err := ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	return &EmailResponse{resp: resp}, nil
}

func (r *Response) SendPasswordResetEmailVerificationCode(ctx context.Context) (*EmailResponse, error) {
	ro, authID, err := r.authenticatorOption("select-authenticator-authenticate", "Email")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err := ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	return &EmailResponse{resp: resp}, nil
}

func (e *EmailResponse) ConfirmEnrollment(ctx context.Context, code string) (*Response, error) {
	if e == nil || e.resp == nil {
		return nil, fmt.Errorf("'SendEnrollmentEmailVerificationCode' should be executed prior to email confirmation")
	}
	ro, err := e.resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(code)))
	return ro.Proceed(ctx, credentials)
}

func (e *EmailResponse) ConfirmReset(ctx context.Context, code string) (*Response, error) {
	if e == nil || e.resp == nil {
		return nil, fmt.Errorf("'SendPasswordResetEmailVerificationCode' should be executed prior to email confirmation")
	}
	ro, err := e.resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(code)))
	return ro.Proceed(ctx, credentials)
}
