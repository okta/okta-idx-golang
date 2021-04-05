package idx

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type UserProfile struct {
	LastName  string `json:"lastName"`
	FirstName string `json:"firstName"`
	Email     string `json:"email"`
}

type userProfileRequest struct {
	UserProfile *UserProfile `json:"userProfile"`
}

func (r *Response) EnrollProfile(ctx context.Context, up *UserProfile) (*Response, error) {
	ro, err := r.remediationOption("select-enroll-profile")
	if err != nil {
		return nil, err
	}
	resp, err := ro.Proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	ro, err = resp.remediationOption("enroll-profile")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(&userProfileRequest{UserProfile: up})
	return ro.Proceed(ctx, b)
}

func (r *Response) SetPassword(ctx context.Context, password string) (*Response, error) {
	ro, authID, err := r.optionWithAuthID("select-authenticator-enroll", "authenticator", "Password")
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
	ro, err = resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(`{
				"credentials": {
					"passcode": "` + strings.TrimSpace(password) + `"
				}
			}`)
	return ro.Proceed(ctx, credentials)
}

type EmailResponse struct {
	resp *Response
}

func (r *Response) SendEmailVerificationCode(ctx context.Context) (*EmailResponse, error) {
	ro, authID, err := r.optionWithAuthID("select-authenticator-enroll", "authenticator", "Email")
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

func (e *EmailResponse) Confirm(ctx context.Context, code string) (*Response, error) {
	if e == nil || e.resp == nil {
		return nil, fmt.Errorf("'SendEmailVerificationCode' should be executed prior to email confirmation")
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

type PhoneResponse struct {
	resp *Response
}

func (r *Response) SendVoiceCallVerificationCode(ctx context.Context, phoneNumber string) (*PhoneResponse, error) {
	return r.sendPhoneVerificationCode(ctx, phoneNumber, "voice")
}

func (r *Response) SendSMSVerificationCode(ctx context.Context, phoneNumber string) (*PhoneResponse, error) {
	return r.sendPhoneVerificationCode(ctx, phoneNumber, "sms")
}

func (r *PhoneResponse) Confirm(ctx context.Context, sms string) (*Response, error) {
	if r == nil || r.resp == nil {
		return nil, fmt.Errorf("'SendSMSVerificationCode' or 'SendVoiceCallVerificationCode` should be executed prior to phone confirmation")
	}
	ro, err := r.resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(sms)))
	return ro.Proceed(ctx, credentials)
}

func (r *Response) Skip(ctx context.Context) (*Response, error) {
	ro, err := r.remediationOption("skip")
	if err != nil {
		return nil, err
	}
	return ro.Proceed(ctx, nil)
}

func (r *Response) sendPhoneVerificationCode(ctx context.Context, phoneNumber, methodType string) (*PhoneResponse, error) {
	ro, authID, err := r.optionWithAuthID("select-authenticator-enroll", "authenticator", "Phone")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "` + methodType + `",
					"phoneNumber": "` + phoneNumber + `"
				}
			}`)
	resp, err := ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	return &PhoneResponse{resp: resp}, nil
}

func (r *Response) optionWithAuthID(optionName, valueName, label string) (*RemediationOption, string, error) {
	ro, err := r.remediationOption(optionName)
	if err != nil {
		return nil, "", err
	}
	v, err := ro.value(valueName)
	if err != nil {
		return nil, "", err
	}
	var authID string
	for _, v := range v.Options {
		if v.Label == label {
			authID = v.Value.(FormOptionsValueObject).Form.Value[0].Value
		}
	}
	if authID == "" {
		return nil, "", fmt.Errorf("could not locate authenticator with the '%s' label", label)
	}
	return ro, authID, nil
}
