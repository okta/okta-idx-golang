package idx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// EnrollmentResponse is used for the profile enrolment flow.
// It holds the initial IdX context object and the list of the available steps.
// At the end of the successful flow, the only enrollment step will be `EnrollmentStepSuccess`
// and tokens will be available
type EnrollmentResponse struct {
	client          *Client
	idxContext      *Context
	token           *Token
	enrollmentSteps []int
}

// UserProfile holds the necessary information to init the enrollment process.
type UserProfile struct {
	LastName  string `json:"lastName"`
	FirstName string `json:"firstName"`
	Email     string `json:"email"`
}

// InitProfileEnroll starts the enrollment process.
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

// SetNewPassword sets new password for the user.
func (r *EnrollmentResponse) SetNewPassword(ctx context.Context, password string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPasswordSetup) {
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

// VerifyEmail sends verification code to the email provided at the first step
func (r *EnrollmentResponse) VerifyEmail(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailVerification) {
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
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.enrollmentSteps = append(r.enrollmentSteps, EnrollmentStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail confirms email address using the provided code
func (r *EnrollmentResponse) ConfirmEmail(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, code)
}

// PhoneMethod represents the method by which the code will be sent to your phone
type PhoneMethod string

const (
	PhoneMethodVoiceCall PhoneMethod = "voice"
	PhoneMethodSMS       PhoneMethod = "sms"
)

// VerifyPhone sends verification code to the provided phone.
// Your phone number should contain a country code
func (r *EnrollmentResponse) VerifyPhone(ctx context.Context, method PhoneMethod, phoneNumber string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneVerification) {
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
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.enrollmentSteps = append(r.enrollmentSteps, EnrollmentStepPhoneConfirmation)
	return r, nil
}

// ConfirmPhone confirms phone number using the provided code
func (r *EnrollmentResponse) ConfirmPhone(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, code)
}

// Skip represents general step to proceed with no action
// It usually appears when other steps are optional
func (r *EnrollmentResponse) Skip(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSkip) {
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

// Cancel the whole enrollment process.
func (r *EnrollmentResponse) Cancel(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepCancel) {
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

// SecurityQuestions represents dict of available security questions.
// Each key represents unique `QuestionKey`, and value represents the human readable question.
type SecurityQuestions map[string]string

// SecurityQuestionOptions returns list of available security questions
func (r *EnrollmentResponse) SecurityQuestionOptions(ctx context.Context) (*EnrollmentResponse, SecurityQuestions, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionOptions) {
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
	for i := range v.Options {
		if v.Options[i].Label == "Choose a security question" {
			obj := v.Options[i].Value.(FormOptionsValueObject).Form.Value
			for j := range obj {
				if obj[j].Name == "questionKey" {
					for k := range obj[j].Options {
						m[string(obj[j].Options[k].Value.(FormOptionsValueString))] = obj[j].Options[k].Label
					}
				}
			}
		}
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, nil, err
	}
	r.enrollmentSteps = append(r.enrollmentSteps, EnrollmentStepSecurityQuestionSetup)
	m["custom"] = "Create a security question"
	return r, m, nil
}

// SecurityQuestion represents security question to be used for the account verification
// In case when 'questionKey'=='custom' the 'question' field should be non-empty and contain custom
// security question.
type SecurityQuestion struct {
	QuestionKey string `json:"questionKey"`
	Question    string `json:"question"`
	Answer      string `json:"answer"`
}

func (r *EnrollmentResponse) SetupSecurityQuestion(ctx context.Context, sq *SecurityQuestion) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionSetup) {
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

// AvailableSteps returns list of human readable steps that can be executed next.
// In case of successful authentication, list will contain only one "SUCCESS" step.
func (r *EnrollmentResponse) AvailableSteps() []string {
	s := make([]string, len(r.enrollmentSteps))
	for i := range r.enrollmentSteps {
		s[i] = stepText[r.enrollmentSteps[i]]
	}
	return s
}

// HasStep checks if the provided step is present in the list of available steps.
func (r *EnrollmentResponse) HasStep(s int) bool {
	for i := range r.enrollmentSteps {
		if r.enrollmentSteps[i] == s {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true in case "SUCCESS"is present in the list of available steps.
func (r *EnrollmentResponse) IsAuthenticated() bool {
	return r.HasStep(EnrollmentStepSuccess)
}

// Token returns authorization token. This method should be called when there is "SUCCESS" step
// present in the list of available steps.
func (r *EnrollmentResponse) Token() *Token {
	return r.token
}

// These codes indicate what method(s) can be called in the next step.
const (
	EnrollmentStepEmailVerification       = iota // 'VerifyEmail'
	EnrollmentStepEmailConfirmation              // 'ConfirmEmail'
	EnrollmentStepPasswordSetup                  // 'SetNewPassword'
	EnrollmentStepPhoneVerification              // 'VerifyPhone'
	EnrollmentStepPhoneConfirmation              // 'ConfirmPhone'
	EnrollmentStepSecurityQuestionOptions        // 'SecurityQuestionOptions'
	EnrollmentStepSecurityQuestionSetup          // 'SetupSecurityQuestion`
	EnrollmentStepCancel                         // 'Cancel'
	EnrollmentStepSkip                           // 'Skip'
	EnrollmentStepSuccess                        // 'Token'
)

var (
	stepText = map[int]string{
		EnrollmentStepEmailVerification:       "EMAIL_VERIFICATION",
		EnrollmentStepEmailConfirmation:       "EMAIL_CONFIRMATION",
		EnrollmentStepPasswordSetup:           "PASSWORD_SETUP",
		EnrollmentStepPhoneVerification:       "PHONE_VERIFICATION",
		EnrollmentStepPhoneConfirmation:       "PHONE_CONFIRMATION",
		EnrollmentStepSecurityQuestionOptions: "SECURITY_QUESTION_OPTIONS",
		EnrollmentStepSecurityQuestionSetup:   "SECURITY_QUESTION_SETUP",
		EnrollmentStepSkip:                    "SKIP",
		EnrollmentStepSuccess:                 "SUCCESS",
		EnrollmentStepCancel:                  "CANCEL",
	}

)

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
		steps = append(steps, EnrollmentStepSecurityQuestionOptions)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		steps = append(steps, EnrollmentStepSkip)
	}
	if len(steps) == 0 {
		return fmt.Errorf("there are no more steps available: %v", resp.Messages.Values)
	}
	r.enrollmentSteps = steps
	return nil
}

func (r *EnrollmentResponse) confirmWithCode(ctx context.Context, code string) (*EnrollmentResponse, error) {
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
