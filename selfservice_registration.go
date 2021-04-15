package idx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type EnrollmentResponse struct {
	client          *Client
	idxContext      *Context
	token           *Token
	enrollmentSteps []int
}

type UserProfile struct {
	LastName  string `json:"lastName"`
	FirstName string `json:"firstName"`
	Email     string `json:"email"`
}

func (c *Client) InitProfileEnroll(ctx context.Context, up *UserProfile) (*EnrollmentResponse, error) {
	idxContext, err := c.Interact(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.Introspect(context.TODO(), idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("select-enroll-profile")
	if err != nil {
		return nil, err
	}
	resp, err = ro.Proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	ro, err = resp.remediationOption("enroll-profile")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(&struct {
		UserProfile *UserProfile `json:"userProfile"`
	}{UserProfile: up})
	resp, err = ro.Proceed(ctx, b)
	if err != nil {
		return nil, err
	}
	er := &EnrollmentResponse{
		idxContext: idxContext,
		client:     c,
	}
	err = er.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return er, nil
}

func (r *EnrollmentResponse) SetNewPasswordOnProfileEnroll(ctx context.Context, password string) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepPasswordSetup) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Password")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.Proceed(ctx, authenticator)
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
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *EnrollmentResponse) VerifyEmailOnProfileEnroll(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepEmailVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Email")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	r.enrollmentSteps = []int{EnrollmentStepEmailConfirmation}
	return r, nil
}

func (r *EnrollmentResponse) ConfirmEmailOnProfileEnroll(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepEmailConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(code)))
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type PhoneMethod string

const (
	PhoneMethodVoiceCall PhoneMethod = "voice"
	PhoneMethodSMS       PhoneMethod = "sms"
)

func (r *EnrollmentResponse) VerifyPhoneOnProfileEnroll(ctx context.Context, method PhoneMethod, phoneNumber string) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepPhoneVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	if method != PhoneMethodVoiceCall && method != PhoneMethodSMS {
		return nil, fmt.Errorf("%s is invalid phone verification method, plese use %s or %s", method, PhoneMethodVoiceCall, PhoneMethodSMS)
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Phone")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "` + string(method) + `",
					"phoneNumber": "` + phoneNumber + `"
				}
			}`)
	resp, err = ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	r.enrollmentSteps = []int{EnrollmentStepPhoneConfirmation}
	return r, nil
}

func (r *EnrollmentResponse) ConfirmPhoneOnProfileEnroll(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepPhoneConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(code)))
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *EnrollmentResponse) Skip(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepSkip) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("skip")
	if err != nil {
		return nil, err
	}
	resp, err = ro.Proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *EnrollmentResponse) Cancel(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepCancel) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	resp, err = resp.Cancel(ctx)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type SecurityQuestions map[string]string

func (r *EnrollmentResponse) SecurityQuestionOptions(ctx context.Context) (*EnrollmentResponse, SecurityQuestions, error) {
	if !r.hasStep(EnrollmentStepSecurityQuestionOption) {
		return nil, nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Security Question")
	if err != nil {
		return nil, nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string)
	ro, err = resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, nil, err
	}
	v, err := ro.value("credentials")
	if err != nil {
		return nil, nil, err
	}
	for _, vo := range v.Options {
		if vo.Label == "Choose a security question" {
			for _, fv := range vo.Value.(FormOptionsValueObject).Form.Value {
				if fv.Name == "questionKey" {
					for _, o := range fv.Options {
						m[string(o.Value.(FormOptionsValueString))] = o.Label
					}
				}
			}
		}
	}
	m["custom"] = "Create a security question"
	r.enrollmentSteps = []int{EnrollmentStepSecurityQuestionSetup}
	return r, m, nil
}

type SecurityQuestion struct {
	QuestionKey string `json:"questionKey"`
	Question    string `json:"question"`
	Answer      string `json:"answer"`
}

func (r *EnrollmentResponse) SetupSecurityQuestion(ctx context.Context, sq *SecurityQuestion) (*EnrollmentResponse, error) {
	if !r.hasStep(EnrollmentStepSecurityQuestionSetup) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	if sq.QuestionKey == "" {
		return nil, errors.New("missing security question key")
	}
	if sq.Answer == "" {
		return nil, errors.New("missing answer for the security question key")
	}
	if sq.QuestionKey == "custom" && sq.Question == "" {
		return nil, errors.New("missing custom question")
	}
	resp, err := r.client.Introspect(ctx, r.idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials, _ := json.Marshal(&struct {
		Credentials *SecurityQuestion `json:"credentials"`
	}{Credentials: sq})
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *EnrollmentResponse) AvailableSteps() []string {
	s := make([]string, len(r.enrollmentSteps))
	for i := range r.enrollmentSteps {
		s[i] = stepText[r.enrollmentSteps[i]]
	}
	return s
}

func (r *EnrollmentResponse) IsAuthenticated() bool {
	return r.hasStep(EnrollmentStepSuccess)
}

func (r *EnrollmentResponse) Token() *Token {
	return r.token
}

const (
	EnrollmentStepEmailVerification = iota
	EnrollmentStepEmailConfirmation
	EnrollmentStepPasswordSetup
	EnrollmentStepPhoneVerification
	EnrollmentStepPhoneConfirmation
	EnrollmentStepSecurityQuestionOption
	EnrollmentStepSecurityQuestionSetup
	EnrollmentStepCancel
	EnrollmentStepSkip
	EnrollmentStepSuccess
)

var stepText = map[int]string{
	EnrollmentStepEmailVerification:      "EMAIL_VERIFICATION",
	EnrollmentStepEmailConfirmation:      "EMAIL_CONFIRMATION",
	EnrollmentStepPasswordSetup:          "PASSWORD_SETUP",
	EnrollmentStepPhoneVerification:      "PHONE_VERIFICATION",
	EnrollmentStepPhoneConfirmation:      "PHONE_CONFIRMATION",
	EnrollmentStepSecurityQuestionOption: "SECURITY_QUESTION_OPTION",
	EnrollmentStepSecurityQuestionSetup:  "SECURITY_QUESTION_SETUP",
	EnrollmentStepSkip:                   "SKIP",
	EnrollmentStepSuccess:                "SUCCESS",
	EnrollmentStepCancel:                 "CANCEL",
}

func (r *EnrollmentResponse) setupNextSteps(ctx context.Context, resp *Response) error {
	if resp.LoginSuccess() {
		exchangeForm := []byte(`{
			"client_secret": "` + r.client.ClientSecret() + `",
			"code_verifier": "` + r.idxContext.CodeVerifier() + `"
		}`)
		tokens, err := resp.SuccessResponse.ExchangeCode(ctx, exchangeForm)
		if err != nil {
			return err
		}
		r.token = tokens
		r.enrollmentSteps = []int{EnrollmentStepSuccess}
		return nil
	}
	var steps []int
	if resp.CancelResponse != nil {
		steps = append(steps, EnrollmentStepCancel)
	}
	_, _, err := resp.authenticatorOption("select-authenticator-enroll", "Password")
	if err == nil {
		steps = append(steps, EnrollmentStepPasswordSetup)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Email")
	if err == nil {
		steps = append(steps, EnrollmentStepEmailVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Phone")
	if err == nil {
		steps = append(steps, EnrollmentStepPhoneVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Question")
	if err == nil {
		steps = append(steps, EnrollmentStepSecurityQuestionOption)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		steps = append(steps, EnrollmentStepSkip)
	}
	r.enrollmentSteps = steps
	return nil
}

func (r *EnrollmentResponse) hasStep(s int) bool {
	for i := range r.enrollmentSteps {
		if r.enrollmentSteps[i] == s {
			return true
		}
	}
	return false
}
