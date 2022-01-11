/**
 * Copyright (c) 2021-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package idx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// EnrollmentResponse is used for the profile enrolment flow. It holds the
// initial IdX context object and the list of the available steps.  At the end
// of the successful flow, the only enrollment step will be
// `EnrollmentStepSuccess` and tokens will be available.
type EnrollmentResponse struct {
	idxContext     *Context
	token          *Token
	availableSteps []EnrollmentStep
	authenticators Authenticators
	contextualData *ContextualData
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
	resp, err := c.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("select-enroll-profile")
	if err != nil {
		return nil, err
	}
	resp, err = ro.proceed(ctx, nil)
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
	resp, err = ro.proceed(ctx, b)
	if err != nil {
		return nil, err
	}
	er := &EnrollmentResponse{
		idxContext: idxContext,
	}
	err = er.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	er.setupAuthenticators(resp)
	return er, nil
}

// EnrollmentSuccess Determines if the enrollment response represents an enrollment success.
func (r *EnrollmentResponse) EnrollmentSuccess() bool {
	if r.HasStep(EnrollmentStepSuccess) && len(r.availableSteps) == 1 {
		return true
	}

	return false
}

// SetNewPassword sets new password for the user.
func (r *EnrollmentResponse) SetNewPassword(ctx context.Context, password string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPasswordSetup) {
		return r.missingStepError(EnrollmentStepPasswordSetup)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Password", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
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
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// OktaVerifyInit Initiate Okta Verify enrollment
func (r *EnrollmentResponse) OktaVerifyInit(ctx context.Context, option OktaVerifyOption) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepOktaVerifyInit) {
		return r.missingStepError(EnrollmentStepOktaVerifyInit)
	}
	resp, err := enrollOktaVerify(ctx, r.idxContext.InteractionHandle, option)
	if err != nil {
		return nil, err
	}
	r.contextualData = resp.CurrentAuthenticator.Value.ContextualData
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(EnrollmentStepOktaVerifyPoll)
	return r, nil
}

// OktaVerifyContinuePolling Determines if the client should continue polling for Okta Verify enrollment.
func (r *EnrollmentResponse) OktaVerifyContinuePolling(ctx context.Context) (*EnrollmentResponse, bool, error) {
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, false, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, false, err
	}

	// Polling should continue if enroll-poll remidation step is present
	if r.HasStep(EnrollmentStepOktaVerifyPoll) {
		return r, true, nil
	}

	return r, false, nil
}

// GoogleAuthInit initiates Google Authenticator setup
func (r *EnrollmentResponse) GoogleAuthInit(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepGoogleAuthenticatorInit) {
		return r.missingStepError(EnrollmentStepGoogleAuthenticatorInit)
	}
	err := r.enrollAuthenticator(ctx, "Google Authenticator")
	if err != nil {
		return nil, err
	}
	r.appendStep(EnrollmentStepGoogleAuthenticatorConfirmation)
	return r, nil
}

func (r *EnrollmentResponse) GoogleAuthConfirm(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepGoogleAuthenticatorConfirmation) {
		return r.missingStepError(EnrollmentStepGoogleAuthenticatorConfirmation)
	}
	defer func() {
		r.contextualData = nil
	}()
	return r.confirmWithCode(ctx, code)
}

// VerifyEmail sends verification code to the email provided at the first step.
func (r *EnrollmentResponse) VerifyEmail(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailVerification) {
		return r.missingStepError(EnrollmentStepEmailVerification)
	}
	resp, err := verifyEmail(ctx, r.idxContext, "select-authenticator-enroll")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(EnrollmentStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail confirms email address using the provided code.
func (r *EnrollmentResponse) ConfirmEmail(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailConfirmation) {
		return r.missingStepError(EnrollmentStepEmailConfirmation)
	}
	return r.confirmWithCode(ctx, code)
}

// PhoneOption represents the method by which the code will be sent to your phone
type PhoneOption string

// PhoneOption constants.
const (
	PhoneMethodVoiceCall PhoneOption = "voice"
	PhoneMethodSMS       PhoneOption = "sms"
)

// OktaVerifyOption is a verify option type.
type OktaVerifyOption string

// OktaVerifyOption constants.
const (
	OktaVerifyOptionQRCode OktaVerifyOption = "qrcode"
	OktaVerifyOptionEmail  OktaVerifyOption = "email"
	OktaVerifyOptionSms    OktaVerifyOption = "sms"
)

// VerifyPhone sends verification code to the provided phone.  Your phone number
// should contain a country code in `+` format e.g. `+11231231234`.
func (r *EnrollmentResponse) VerifyPhone(ctx context.Context, option PhoneOption, phoneNumber string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneVerification) {
		return r.missingStepError(EnrollmentStepPhoneVerification)
	}
	resp, err := verifyPhone(ctx, "select-authenticator-enroll", r.idxContext.InteractionHandle, option, phoneNumber)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(EnrollmentStepPhoneConfirmation)
	return r, nil
}

// ConfirmPhone confirms phone number using the provided code.
func (r *EnrollmentResponse) ConfirmPhone(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneConfirmation) {
		return r.missingStepError(EnrollmentStepPhoneConfirmation)
	}
	return r.confirmWithCode(ctx, code)
}

// WebAuthNSetup initiates WebAuthN setup
func (r *EnrollmentResponse) WebAuthNSetup(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepWebAuthNSetup) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	err := r.enrollAuthenticator(ctx, "Security Key or Biometric")
	if err != nil {
		return nil, err
	}
	r.appendStep(EnrollmentStepWebAuthNVerify)
	return r, nil
}

type WebAuthNCredentials struct {
	Attestation string `json:"attestation"`
	ClientData  string `json:"clientData"`
}

// WebAuthNVerify enrolls user's Security Key or Biometric
func (r *EnrollmentResponse) WebAuthNVerify(ctx context.Context, credentials *WebAuthNCredentials) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepWebAuthNVerify) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	if credentials == nil {
		return nil, errors.New("invalid credentials")
	}
	resp, err := webAuthNCredentials(ctx, r.idxContext, "enroll-authenticator", credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Skip represents general step to proceed with no action.  It usually appears
// when other steps are optional.
func (r *EnrollmentResponse) Skip(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSkip) {
		return r.missingStepError(EnrollmentStepSkip)
	}
	resp, err := skip(ctx, r.idxContext.InteractionHandle)
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
		return r.missingStepError(EnrollmentStepCancel)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
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

// SecurityQuestions represents dict of available security questions.  Each key
// represents unique `QuestionKey`, and value represents the human readable
// question.
type SecurityQuestions map[string]string

// SecurityQuestionOptions returns list of available security questions.
func (r *EnrollmentResponse) SecurityQuestionOptions(ctx context.Context) (*EnrollmentResponse, SecurityQuestions, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionOptions) {
		resp, err := r.missingStepError(EnrollmentStepSecurityQuestionOptions)
		return resp, nil, err
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Security Question", true)
	if err != nil {
		return nil, nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
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
	r.appendStep(EnrollmentStepSecurityQuestionSetup)
	m["custom"] = "Create a security question"
	return r, m, nil
}

// SecurityQuestion represents security question to be used for the account verification.
// In case when 'questionKey'=='custom' the 'question' field should be non-empty and contain custom
// security question.
type SecurityQuestion struct {
	QuestionKey string `json:"questionKey"`
	Question    string `json:"question"`
	Answer      string `json:"answer"`
}

// SetupSecurityQuestion sets up the security question.
func (r *EnrollmentResponse) SetupSecurityQuestion(ctx context.Context, sq *SecurityQuestion) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionSetup) {
		return r.missingStepError(EnrollmentStepSecurityQuestionSetup)
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
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
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
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// AvailableSteps returns list of steps that can be executed next.  In case of
// successful authentication, list will contain only one "SUCCESS" step.
func (r *EnrollmentResponse) AvailableSteps() []EnrollmentStep {
	return r.availableSteps
}

// HasStep checks if the provided step is present in the list of available
// steps.
func (r *EnrollmentResponse) HasStep(s EnrollmentStep) bool {
	for i := range r.availableSteps {
		if r.availableSteps[i] == s {
			return true
		}
	}
	return false
}

func (r *EnrollmentResponse) ContextualData() *ContextualData {
	return r.contextualData
}

// Authenticators returns the Authenticators.
func (r *EnrollmentResponse) Authenticators() Authenticators {
	return r.authenticators
}

// IsAuthenticated returns true in case "SUCCESS" is present in the list of
// available steps.
func (r *EnrollmentResponse) IsAuthenticated() bool {
	return r.HasStep(EnrollmentStepSuccess)
}

// Token returns authorization token. This method should be called when there is
// "SUCCESS" step present in the list of available steps.
func (r *EnrollmentResponse) Token() *Token {
	return r.token
}

func (r *EnrollmentResponse) WhereAmI(ctx context.Context) (*EnrollmentResponse, error) {
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type EnrollmentStep int

// String is a string representation of the enrollment step.
func (s EnrollmentStep) String() string {
	v, ok := enrollStepText[s]
	if ok {
		return v
	}
	return unknownStep
}

// These codes indicate what method(s) can be called in the next step.
const (
	EnrollmentStepEmailVerification               EnrollmentStep = iota + 1 // 'VerifyEmail'
	EnrollmentStepEmailConfirmation                                         // 'ConfirmEmail'
	EnrollmentStepPasswordSetup                                             // 'SetNewPassword'
	EnrollmentStepPhoneVerification                                         // 'VerifyPhone'
	EnrollmentStepPhoneConfirmation                                         // 'ConfirmPhone'
	EnrollmentStepSecurityQuestionOptions                                   // 'SecurityQuestionOptions'
	EnrollmentStepSecurityQuestionSetup                                     // 'SetupSecurityQuestion`
	EnrollmentStepOktaVerifyInit                                            // `OktaVerifyInit`
	EnrollmentStepOktaVerifyPoll                                            // `OktaVerifyPoll`
	EnrollmentStepGoogleAuthenticatorInit                                   // `GoogleAuthInitialVerify`
	EnrollmentStepGoogleAuthenticatorConfirmation                           // `GoogleAuthConfirm`
	EnrollmentStepWebAuthNSetup                                             // `WebAuthNSetup`
	EnrollmentStepWebAuthNVerify                                            // `WebAuthNVerify`
	EnrollmentStepCancel                                                    // 'Cancel'
	EnrollmentStepSkip                                                      // 'Skip'
	EnrollmentStepSuccess                                                   // 'Token'
)

var enrollStepText = map[EnrollmentStep]string{
	EnrollmentStepEmailVerification:               "EMAIL_VERIFICATION",
	EnrollmentStepEmailConfirmation:               "EMAIL_CONFIRMATION",
	EnrollmentStepPasswordSetup:                   "PASSWORD_SETUP",
	EnrollmentStepPhoneVerification:               "PHONE_VERIFICATION",
	EnrollmentStepPhoneConfirmation:               "PHONE_CONFIRMATION",
	EnrollmentStepSecurityQuestionOptions:         "SECURITY_QUESTION_OPTIONS",
	EnrollmentStepSecurityQuestionSetup:           "SECURITY_QUESTION_SETUP",
	EnrollmentStepOktaVerifyInit:                  "OKTA_VERIFY_INIT",
	EnrollmentStepOktaVerifyPoll:                  "OKTA_VERIFY_POLL",
	EnrollmentStepGoogleAuthenticatorInit:         "GOOGLE_AUTHENTICATOR_INIT",
	EnrollmentStepGoogleAuthenticatorConfirmation: "GOOGLE_AUTHENTICATOR_CONFIRM",
	EnrollmentStepWebAuthNSetup:                   "WEB_AUTHN_SETUP",
	EnrollmentStepWebAuthNVerify:                  "WEB_AUTHN_VERIFY",
	EnrollmentStepCancel:                          "CANCEL",
	EnrollmentStepSkip:                            "SKIP",
	EnrollmentStepSuccess:                         "SUCCESS",
}

func (r *EnrollmentResponse) setupNextSteps(ctx context.Context, resp *Response) error {
	if resp.LoginSuccess() {
		exchangeForm := []byte(`{
			"client_secret": "` + idx.ClientSecret() + `",
			"code_verifier": "` + r.idxContext.CodeVerifier + `"
		}`)
		tokens, err := resp.SuccessResponse.exchangeCode(ctx, exchangeForm)
		if err != nil {
			return err
		}
		r.token = tokens
		r.availableSteps = []EnrollmentStep{EnrollmentStepSuccess}
		return nil
	}
	// resets steps
	r.availableSteps = []EnrollmentStep{}

	if resp.CancelResponse != nil {
		r.appendStep(EnrollmentStepCancel)
	}
	_, _, err := resp.authenticatorOption("select-authenticator-enroll", "Password", false)
	if err == nil {
		r.appendStep(EnrollmentStepPasswordSetup)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Email", false)
	if err == nil {
		r.appendStep(EnrollmentStepEmailVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Phone", false)
	if err == nil {
		r.appendStep(EnrollmentStepPhoneVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Question", false)
	if err == nil {
		r.appendStep(EnrollmentStepSecurityQuestionOptions)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Okta Verify", false)
	if err == nil {
		r.appendStep(EnrollmentStepOktaVerifyInit)
	}
	_, err = resp.remediationOption("enroll-poll")
	if err == nil {
		r.appendStep(EnrollmentStepOktaVerifyPoll)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Google Authenticator", false)
	if err == nil {
		r.appendStep(EnrollmentStepGoogleAuthenticatorInit)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Key or Biometric", false)
	if err == nil {
		r.appendStep(EnrollmentStepWebAuthNSetup)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		r.appendStep(EnrollmentStepSkip)
	}
	if len(r.availableSteps) == 0 {
		return fmt.Errorf("there are no more steps available: %v", resp.Messages.Values)
	}
	return nil
}

func (r *EnrollmentResponse) setupAuthenticators(resp *Response) {
	r.authenticators = resp.Authenticators
}

func (r *EnrollmentResponse) confirmWithCode(ctx context.Context, code string) (*EnrollmentResponse, error) {
	resp, err := passcodeAuth(ctx, r.idxContext, "enroll-authenticator", code)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *EnrollmentResponse) missingStepError(missingStep EnrollmentStep) (*EnrollmentResponse, error) {
	steps := ""
	for index, step := range r.availableSteps {
		if index != 0 {
			steps = fmt.Sprintf("%s, ", steps)
		}
		steps = fmt.Sprintf("%s%q", steps, step)
	}
	return nil, fmt.Errorf("%q enrollment step is not available, please try one of %s", missingStep, steps)
}

func (r *EnrollmentResponse) appendStep(step EnrollmentStep) {
	for _, _step := range r.availableSteps {
		if step == _step {
			return
		}
	}
	r.availableSteps = append(r.availableSteps, step)
}

func (r *EnrollmentResponse) enrollAuthenticator(ctx context.Context, authenticatorLabel string) error {
	resp, err := enrollAuthenticator(ctx, r.idxContext.InteractionHandle, authenticatorLabel)
	if err != nil {
		return err
	}
	r.contextualData = resp.CurrentAuthenticator.Value.ContextualData
	return r.setupNextSteps(ctx, resp)
}
