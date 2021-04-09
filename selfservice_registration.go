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

func (r *Response) SetPasswordOnEnroll(ctx context.Context, password string) (*Response, error) {
	ro, authID, err := r.authenticatorOption("select-authenticator-enroll", "Password")
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

type PhoneResponse struct {
	resp *Response
}

func (r *Response) SendVoiceCallVerificationCode(ctx context.Context, phoneNumber string) (*PhoneResponse, error) {
	return r.sendPhoneVerificationCode(ctx, phoneNumber, "voice")
}

func (r *Response) SendSMSVerificationCode(ctx context.Context, phoneNumber string) (*PhoneResponse, error) {
	return r.sendPhoneVerificationCode(ctx, phoneNumber, "sms")
}

func (r *PhoneResponse) ConfirmEnrollment(ctx context.Context, sms string) (*Response, error) {
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

func (r *Response) CanSkip() bool {
	_, err := r.remediationOption("skip")
	return err == nil
}

func (r *Response) sendPhoneVerificationCode(ctx context.Context, phoneNumber, methodType string) (*PhoneResponse, error) {
	ro, authID, err := r.authenticatorOption("select-authenticator-enroll", "Phone")
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

func (r *Response) authenticatorOption(optionName, label string) (*RemediationOption, string, error) {
	ro, err := r.remediationOption(optionName)
	if err != nil {
		return nil, "", err
	}
	v, err := ro.value("authenticator")
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
