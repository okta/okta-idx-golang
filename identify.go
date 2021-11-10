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
	"time"
)

type LoginResponse struct {
	idxContext        *Context
	token             *Token
	availableSteps    []LoginStep
	identifyProviders []IdentityProvider
	contextualData    *ContextualData
}

type AuthenticationOptions struct {
	UserName string
	Password string
    ActivationToken string
}

type IdentityProvider struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Method string `json:"method"`
}

type LoginResponse struct {
	idxContext        *Context
	token             *Token
	availableSteps    []LoginStep
	identifyProviders []IdentityProvider
}

type LoginStep int

// InitLogin Initialize the IDX login.
func (c *Client) InitLogin(ctx context.Context) (*LoginResponse, error) {
	idxContext, err := c.Interact(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	lr := &LoginResponse{
		idxContext: idxContext,
	}
	err = lr.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return lr, nil
}

// Authenticate is an identification flow with username and password, or optional activation token
func (c *Client) Authenticate(ctx context.Context, authenticationOptions *AuthenticationOptions) (*LoginResponse, error) {
	lr, err := c.InitLogin(ctx)
	if err != nil {
		return nil, err
	}

	ir := &IdentifyRequest{
		Identifier: authenticationOptions.UserName,
		Credentials: Credentials{
			Password: authenticationOptions.Password,
		},
	}

	return lr.Identify(ctx, ir)
}

// Identify Perform identification.
func (r *LoginResponse) Identify(ctx context.Context, ir *IdentifyRequest) (*LoginResponse, error) {
	if !r.HasStep(LoginStepIdentify) {
		return r.missingStepError(LoginStepIdentify)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption(option)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(ir)
	resp, err = ro.proceed(ctx, b)
	if err != nil {
		return nil, err
	}
	resp, err = setPasswordOnDemand(ctx, resp, ir.Credentials.Password)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SetNewPassword Set new password.
func (r *LoginResponse) SetNewPassword(ctx context.Context, password string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepSetupNewPassword) {
		return r.missingStepError(LoginStepSetupNewPassword)
	}
	resp, err := setPassword(ctx, r.idxContext, "reenroll-authenticator", password)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// WhereAmI Provides introspection of the login response.
func (r *LoginResponse) WhereAmI(ctx context.Context) (*LoginResponse, error) {
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

//nolint:gocognit,gocritic
// OktaVerifyMethodTypes Given OktaVerify step is available, return the
// available method types as a string slice. Possible values `totp` and `push`
// at the present time
func (r *LoginResponse) OktaVerifyMethodTypes(ctx context.Context) ([]string, error) {
	methodTypes := []string{}
	if !r.HasStep(LoginStepOktaVerify) {
		_, err := r.missingStepError(LoginStepOktaVerify)
		return methodTypes, err
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return methodTypes, err
	}
	ro, _, err := resp.authenticatorOption("select-authenticator-authenticate", "Okta Verify", true)
	if err != nil {
		return methodTypes, err
	}

	for _, val := range ro.FormValues {
		if val.Name != "authenticator" {
			continue
		}

		for _, opt := range val.Options {
			if opt.Label != "Okta Verify" {
				continue
			}

			if fovo, ok := opt.Value.(FormOptionsValueObject); ok {
				for _, val := range fovo.Form.Value {
					if val.Name != "methodType" {
						continue
					}

					for _, opt := range val.Options {
						if str, ok := opt.Value.(FormOptionsValueString); ok {
							methodTypes = append(methodTypes, string(str))
						}
					}
				}
			}
		}
	}

	return methodTypes, err
}

// OktaVerify Perform Okta Verify verification. This method blocks in a polling manner.
func (r *LoginResponse) OktaVerify(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepOktaVerify) {
		return r.missingStepError(LoginStepOktaVerify)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Okta Verify", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "push"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	ro, err = resp.remediationOption("challenge-poll")
	if err != nil {
		return nil, err
	}
	t := time.NewTicker(defaultPollInterval)

loop:
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
			resp, err = ro.proceed(ctx, nil)
			if err != nil {
				return nil, err
			}
			ro, err = resp.remediationOption("challenge-poll")
			if err != nil {
				break loop
			}
		}
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// OktaVerifyConfirm Confirm that the given code is from the correct okta verify registration.
func (r *LoginResponse) OktaVerifyConfirm(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepOktaVerify) {
		return r.missingStepError(LoginStepOktaVerify)
	}
	defer func() {
		r.contextualData = nil
	}()
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Okta Verify", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "totp"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}

	ro, err = resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}

	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"totp": "%s"
				}
			}`, strings.TrimSpace(code)))
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}

	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, err
}

// GoogleAuthInitialVerify initiates Google Authenticator setup for the existing user in case this authenticator
// was reset or wasn't set up previously.
func (r *LoginResponse) GoogleAuthInitialVerify(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepGoogleAuthenticatorInitialVerification) {
		return r.missingStepError(LoginStepGoogleAuthenticatorInitialVerification)
	}
	err := r.enrollAuthenticator(ctx, "Google Authenticator")
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepGoogleAuthenticatorConfirmation)
	return r, nil
}

func (r *LoginResponse) GoogleAuthConfirm(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepGoogleAuthenticatorConfirmation) {
		return r.missingStepError(LoginStepGoogleAuthenticatorConfirmation)
	}
	defer func() {
		r.contextualData = nil
	}()
	resp, err := r.confirmWithCode(ctx, "challenge-authenticator", code)
	if err != nil && strings.Contains(err.Error(), "could not locate a remediation option with the name 'challenge-authenticator'") {
		return r.confirmWithCode(ctx, "enroll-authenticator", code)
	}
	return resp, err
}

func (r *LoginResponse) WebAuthNSetup(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepWebAuthNSetup) {
		return r.missingStepError(LoginStepWebAuthNSetup)
	}
	err := r.enrollAuthenticator(ctx, "Security Key or Biometric")
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepWebAuthNInitialVerify)
	return r, nil
}

func (r *LoginResponse) WebAuthNInitialVerify(ctx context.Context, credentials *WebAuthNVerifyCredentials) (*LoginResponse, error) {
	if !r.HasStep(LoginStepWebAuthNInitialVerify) {
		return r.missingStepError(LoginStepWebAuthNInitialVerify)
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

func (r *LoginResponse) WebAuthNChallenge(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepWebAuthNChallenge) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Security Key or Biometric", true)
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
	for _, v := range resp.AuthenticatorEnrollments.Value {
		if v.Key == "webauthn" {
			resp.CurrentAuthenticator.Value.ContextualData.ChallengeData.CredentialID = v.CredentialID
		}
	}
	r.contextualData = resp.CurrentAuthenticator.Value.ContextualData
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepWebAuthNVerify)
	return r, nil
}

type WebAuthNChallengeCredentials struct {
	ClientData        string `json:"clientData"`
	AuthenticatorData string `json:"authenticatorData"`
	SignatureData     string `json:"signatureData"`
}

func (r *LoginResponse) WebAuthNVerify(ctx context.Context, credentials *WebAuthNChallengeCredentials) (*LoginResponse, error) {
	if !r.HasStep(LoginStepWebAuthNVerify) {
		return r.missingStepError(LoginStepWebAuthNVerify)
	}
	if credentials == nil {
		return nil, errors.New("invalid credentials")
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}

	data := []byte(fmt.Sprintf(`{
				"credentials": {
        				"clientData": "%s",
        				"authenticatorData": "%s",
        				"signatureData": "%s"
				}
			}`, credentials.ClientData, credentials.AuthenticatorData, credentials.SignatureData))
	resp, err = ro.proceed(ctx, data)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	return r, err
}

func (r *LoginResponse) ContextualData() *ContextualData {
	return r.contextualData
}

// ConfirmPhone Confirms a phone given the identification code.
func (r *LoginResponse) ConfirmPhone(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepPhoneConfirmation) {
		return r.missingStepError(LoginStepPhoneConfirmation)
	}
	resp, err := r.confirmWithCode(ctx, "challenge-authenticator", code)
	// this might indicate that a user set ups the phone for the first time
	if err != nil && strings.Contains(err.Error(), "could not locate a remediation option with the name 'challenge-authenticator'") {
		return r.confirmWithCode(ctx, "enroll-authenticator", code)
	}
	return resp, err
}

// VerifyPhone Triggers phone verification code emission.
func (r *LoginResponse) VerifyPhone(ctx context.Context, option PhoneOption) (*LoginResponse, error) {
	if !r.HasStep(LoginStepPhoneVerification) {
		return r.missingStepError(LoginStepPhoneVerification)
	}
	resp, err := verifyPhone(ctx, "select-authenticator-authenticate", r.idxContext.InteractionHandle, option, "")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepPhoneConfirmation)
	return r, nil
}

// VerifyPhoneInitial Initial verify phone.
func (r *LoginResponse) VerifyPhoneInitial(ctx context.Context, option PhoneOption, phoneNumber string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepPhoneInitialVerification) {
		return r.missingStepError(LoginStepPhoneInitialVerification)
	}
	resp, err := verifyPhone(ctx, "select-authenticator-enroll", r.idxContext.InteractionHandle, option, phoneNumber)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepPhoneConfirmation)
	return r, nil
}

func verifyPhone(ctx context.Context, remedOpt string, ih *InteractionHandle, phoneOpt PhoneOption, phoneNumber string) (*Response, error) {
	if phoneOpt != PhoneMethodVoiceCall && phoneOpt != PhoneMethodSMS {
		return nil, fmt.Errorf("%s is invalid phone verification option, plese use %s or %s", phoneOpt, PhoneMethodVoiceCall, PhoneMethodSMS)
	}
	resp, err := idx.introspect(ctx, ih)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption(remedOpt, "Phone", true)
	if err != nil {
		return nil, err
	}
	var authenticator []byte
	if phoneNumber != "" {
		authenticator = []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "` + string(phoneOpt) + `",
					"phoneNumber": "` + phoneNumber + `"
				}
			}`)
	} else {
		authenticator = []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "` + string(phoneOpt) + `"
				}
			}`)
	}
	return ro.proceed(ctx, authenticator)
}

// VerifyEmail Triggers email verification code emission.
func (r *LoginResponse) VerifyEmail(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepEmailVerification) {
		return r.missingStepError(LoginStepEmailVerification)
	}
	resp, err := verifyEmail(ctx, r.idxContext, "select-authenticator-authenticate")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(LoginStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail Confirm the verified email with the given code that was emitted.
func (r *LoginResponse) ConfirmEmail(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepEmailConfirmation) {
		return r.missingStepError(LoginStepEmailConfirmation)
	}
	return r.confirmWithCode(ctx, "challenge-authenticator", code)
}

func (r *LoginResponse) SecurityQuestionOptions(ctx context.Context) (*LoginResponse, SecurityQuestions, error) {
	if !r.HasStep(LoginStepSecurityQuestionOptions) {
		_, err := r.missingStepError(LoginStepOktaVerify)
		return nil, nil, err
	}
	resp, questions, err := securityQuestionOptions(ctx, r.idxContext)
	if err != nil {
		return nil, nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, nil, err
	}
	r.appendStep(LoginStepSecurityQuestionSetup)
	return r, questions, nil
}

func (r *LoginResponse) SecurityQuestionSetup(ctx context.Context, sq *SecurityQuestion) (*LoginResponse, error) {
	if !r.HasStep(LoginStepSecurityQuestionSetup) {
		return r.missingStepError(LoginStepSecurityQuestionSetup)
	}
	resp, err := securityQuestionSetup(ctx, r.idxContext, sq)
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
func (r *LoginResponse) Skip(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepSkip) {
		return r.missingStepError(LoginStepSkip)
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

// Cancel the whole login process.
func (r *LoginResponse) Cancel(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepCancel) {
		return r.missingStepError(LoginStepCancel)
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

// AvailableSteps returns list of steps that can be executed next.  In case of
// successful authentication, list will contain only one "SUCCESS" step.
func (r *LoginResponse) AvailableSteps() []LoginStep {
	return r.availableSteps
}

// IdentityProviders List of identity providers.
func (r *LoginResponse) IdentityProviders() []IdentityProvider {
	return r.identifyProviders
}

// HasStep checks if the provided step is present in the list of available
// steps.
func (r *LoginResponse) HasStep(s LoginStep) bool {
	for i := range r.availableSteps {
		if r.availableSteps[i] == s {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true in case "SUCCESS" is present in the list of available steps.
func (r *LoginResponse) IsAuthenticated() bool {
	return r.HasStep(LoginStepSuccess)
}

// Token returns authorization token. This method should be called when there is "SUCCESS" step
// present in the list of available steps.
func (r *LoginResponse) Token() *Token {
	return r.token
}

// Context The IDX Context
// present in the list of available steps.
func (r *LoginResponse) Context() *Context {
	return r.idxContext
}

// String representation of LoginStep.
func (s LoginStep) String() string {
	v, ok := loginStepText[s]
	if ok {
		return v
	}
	return unknownStep
}

var loginStepText = map[LoginStep]string{
	LoginStepIdentify:                               "IDENTIFY",
	LoginStepSetupNewPassword:                       "SETUP_NEW_PASSWORD",
	LoginStepProviderIdentify:                       "PROVIDER_IDENTIFY",
	LoginStepEmailVerification:                      "EMAIL_VERIFICATION",
	LoginStepEmailConfirmation:                      "EMAIL_CONFIRMATION",
	LoginStepPhoneVerification:                      "PHONE_VERIFICATION",
	LoginStepPhoneInitialVerification:               "PHONE_INITIAL_VERIFICATION",
	LoginStepPhoneConfirmation:                      "PHONE_CONFIRMATION",
	LoginStepSecurityQuestionOptions:                "SECURITY_QUESTION_OPTIONS",
	LoginStepSecurityQuestionSetup:                  "SECURITY_QUESTION_SETUP",
	LoginStepAnswerSecurityQuestion:                 "ANSWER_SECURITY_QUESTION",
	LoginStepOktaVerify:                             "OKTA_VERIFY",
	LoginStepGoogleAuthenticatorInitialVerification: "GOOGLE_AUTHENTICATOR_INITIAL_VERIFICATION",
	LoginStepGoogleAuthenticatorConfirmation:        "GOOGLE_AUTHENTICATOR_CONFIRMATION",
	LoginStepWebAuthNSetup:                          "WEB_AUTHN_SETUP",
	LoginStepWebAuthNInitialVerify:                  "WEB_AUTHN_INITIAL_VERIFY",
	LoginStepWebAuthNChallenge:                      "WEB_AUTHN_CHALLENGE",
	LoginStepWebAuthNVerify:                         "WEB_AUTHN_VERIFY",
	LoginStepCancel:                                 "CANCEL",
	LoginStepSkip:                                   "SKIP",
	LoginStepSuccess:                                "SUCCESS",
}

// These codes indicate what method(s) can be called in the next step.
const (
	LoginStepIdentify                               LoginStep = iota + 1 // 'Identify'
	LoginStepSetupNewPassword                                            // 'SetupNewPassword'
	LoginStepProviderIdentify                                            // 'Providers'
	LoginStepEmailVerification                                           // 'VerifyEmail'
	LoginStepEmailConfirmation                                           // 'ConfirmEmail'
	LoginStepPhoneVerification                                           // 'VerifyPhone'
	LoginStepPhoneInitialVerification                                    // 'InitialVerifyPhone'
	LoginStepPhoneConfirmation                                           // 'ConfirmPhone'
	LoginStepSecurityQuestionOptions                                     // 'SecurityQuestionOptions'
	LoginStepSecurityQuestionSetup                                       // 'SecurityQuestionSetup'
	LoginStepOktaVerify                                                  // 'OktaVerify'
	LoginStepGoogleAuthenticatorInitialVerification                      // `GoogleAuthInitialVerify`
	LoginStepGoogleAuthenticatorConfirmation                             // `GoogleAuthConfirm`
	LoginStepWebAuthNSetup                                               // `WebAuthNSetup`
	LoginStepWebAuthNInitialVerify                                       // `WebAuthNInitialVerify`
	LoginStepWebAuthNChallenge                                           // `WebAuthNChallenge`
	LoginStepWebAuthNVerify                                              // `WebAuthNVerify`
	LoginStepCancel                                                      // 'Cancel'
	LoginStepSkip                                                        // 'Skip'
	LoginStepSuccess                                                     // 'Token'
)

// nolint
func (r *LoginResponse) setupNextSteps(ctx context.Context, resp *Response) error {
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
		r.availableSteps = []LoginStep{LoginStepSuccess}
		return nil
	}

	// resets steps
	r.availableSteps = []LoginStep{}

	if resp.CancelResponse != nil {
		r.appendStep(LoginStepCancel)
	}

	_, err := resp.remediationOption("identify")
	if err == nil {
		r.appendStep(LoginStepIdentify)
	}

	_, err = resp.remediationOption("select-authenticator-enroll")
	if err == nil {
		steps = append(steps, LoginStepAuthenticatorEnroll)
	}

	ros, err := resp.remediationOptions("redirect-idp")
	if err == nil {
		r.identifyProviders = make([]IdentityProvider, len(ros))
		for i := range ros {
			r.identifyProviders[i] = IdentityProvider{
				Type:   ros[i].OptionType,
				Name:   ros[i].IDP.Name,
				URL:    ros[i].Href,
				Method: ros[i].Method,
			}
		}
		r.appendStep(LoginStepProviderIdentify)
	} else {
		r.identifyProviders = nil
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Email", false)
	if err == nil {
		r.appendStep(LoginStepEmailVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Phone", false)
	if err == nil {
		r.appendStep(LoginStepPhoneVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Okta Verify", false)
	if err == nil {
		r.appendStep(LoginStepOktaVerify)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Google Authenticator", false)
	if err == nil {
		r.appendStep(LoginStepGoogleAuthenticatorConfirmation)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Security Key or Biometric", false)
	if err == nil {
		r.appendStep(LoginStepWebAuthNChallenge)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Phone", false)
	if err == nil {
		r.appendStep(LoginStepPhoneInitialVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Okta Verify", false)
	if err == nil {
		r.appendStep(LoginStepOktaVerify)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Google Authenticator", false)
	if err == nil {
		r.appendStep(LoginStepGoogleAuthenticatorInitialVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Key or Biometric", false)
	if err == nil {
		r.appendStep(LoginStepWebAuthNSetup)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Question", false)
	if err == nil {
		r.appendStep(LoginStepSecurityQuestionOptions)
	}
	ro, err := resp.remediationOption("reenroll-authenticator")
	if err == nil {
		v, _ := ro.value("credentials")
		if v != nil && v.Form != nil {
			for i := range v.Form.FormValues {
				if v.Form.FormValues[i].Label == "New password" {
					r.appendStep(LoginStepSetupNewPassword)
				}
			}
		}
	}

	_, err = resp.remediationOption("skip")
	if err == nil {
		r.appendStep(LoginStepSkip)
	}
	if len(r.availableSteps) == 0 {
		return fmt.Errorf("there are no more steps available: %+v", resp.Messages.Values)
	}
	return nil
}

func (r *LoginResponse) confirmWithCode(ctx context.Context, remediationOpt, code string) (*LoginResponse, error) {
	resp, err := passcodeAuth(ctx, r.idxContext, remediationOpt, code)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	return r, err
}

func setPasswordOnDemand(ctx context.Context, resp *Response, password string) (*Response, error) {
	if resp.CurrentAuthenticatorEnrollment != nil && resp.CurrentAuthenticatorEnrollment.Value.Key == "okta_password" {
		challengeAuthenticator, err := resp.remediationOption("challenge-authenticator")
		if err == nil {
			return sendPasscode(ctx, challengeAuthenticator, password)
		}
	}
	ro, authID, _ := resp.authenticatorOption("select-authenticator-authenticate", "Password", true)
	if ro == nil {
		return resp, nil
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err := ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	challengeAuthenticator, err := resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	return sendPasscode(ctx, challengeAuthenticator, password)
}

func sendPasscode(ctx context.Context, challengeAuthenticator *RemediationOption, password string) (*Response, error) {
	credentials := []byte(`{
		"credentials": {
			"passcode": "` + strings.TrimSpace(password) + `"
		}
	}`)
	return challengeAuthenticator.proceed(ctx, credentials)
}

func (r *LoginResponse) enrollAuthenticator(ctx context.Context, authenticatorLabel string) error {
	resp, err := enrollAuthenticator(ctx, r.idxContext.InteractionHandle, authenticatorLabel)
	if err != nil {
		return err
	}
	r.contextualData = resp.CurrentAuthenticator.Value.ContextualData
	return r.setupNextSteps(ctx, resp)
}

func enrollOktaVerify(ctx context.Context, handle *InteractionHandle, option OktaVerifyOption) (*Response, error) {
	resp, err := idx.introspect(ctx, handle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Okta Verify", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"channel": "` + string(option) + `"
				}
			}`)
	return ro.proceed(ctx, authenticator)
}

func (r *LoginResponse) missingStepError(missingStep LoginStep) (*LoginResponse, error) {
	steps := ""
	for index, step := range r.availableSteps {
		if index != 0 {
			steps = fmt.Sprintf("%s, ", steps)
		}
		steps = fmt.Sprintf("%s%q", steps, step)
	}
	return nil, fmt.Errorf("%q login step is not available, please try one of %s", missingStep, steps)
}

func (r *LoginResponse) appendStep(step LoginStep) {
	for _, _step := range r.availableSteps {
		if step == _step {
			return
		}
	}
	r.availableSteps = append(r.availableSteps, step)
}
