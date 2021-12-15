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

type IdentityProvider struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Method string `json:"method"`
}

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

// Identify Perform identification.
func (r *LoginResponse) Identify(ctx context.Context, ir *IdentifyRequest) (*LoginResponse, error) {
	if !r.HasStep(LoginStepIdentify) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("identify")
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
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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

// OktaVerify Perform verification.
func (r *LoginResponse) OktaVerify(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepOktaVerify) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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

// GoogleAuthInitialVerify initiates Google Authenticator setup for the existing user in case this authenticator
// was reset or wasn't set up previously.
func (r *LoginResponse) GoogleAuthInitialVerify(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepGoogleAuthenticatorInitialVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := enrollGoogleAuth(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	r.contextualData = resp.CurrentAuthenticator.Value.ContextualData
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, LoginStepGoogleAuthenticatorConfirmation)
	return r, nil
}

func (r *LoginResponse) GoogleAuthConfirm(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepGoogleAuthenticatorConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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

func (r *LoginResponse) ContextualData() *ContextualData {
	return r.contextualData
}

// ConfirmPhone Confirms a phone given the identification code.
func (r *LoginResponse) ConfirmPhone(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepPhoneConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := verifyPhone(ctx, "select-authenticator-authenticate", r.idxContext.InteractionHandle, option, "")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, LoginStepPhoneConfirmation)
	return r, nil
}

// VerifyPhoneInitial Initial verify phone.
func (r *LoginResponse) VerifyPhoneInitial(ctx context.Context, option PhoneOption, phoneNumber string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepPhoneInitialVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := verifyPhone(ctx, "select-authenticator-enroll", r.idxContext.InteractionHandle, option, phoneNumber)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, LoginStepPhoneConfirmation)
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
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := verifyEmail(ctx, r.idxContext, "select-authenticator-authenticate")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, LoginStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail Confirm the verified email with the given code that was emitted.
func (r *LoginResponse) ConfirmEmail(ctx context.Context, code string) (*LoginResponse, error) {
	if !r.HasStep(LoginStepEmailConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, "challenge-authenticator", code)
}

// Skip represents general step to proceed with no action.  It usually appears
// when other steps are optional.
func (r *LoginResponse) Skip(ctx context.Context) (*LoginResponse, error) {
	if !r.HasStep(LoginStepSkip) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
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

type LoginStep int

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
	LoginStepAnswerSecurityQuestion:                 "ANSWER SECURITY_QUESTION",
	LoginStepOktaVerify:                             "OKTA_VERIFY",
	LoginStepGoogleAuthenticatorInitialVerification: "GOOGLE_AUTHENTICATOR_INITIAL_VERIFICATION",
	LoginStepGoogleAuthenticatorConfirmation:        "GOOGLE_AUTHENTICATOR_CONFIRMATION",
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
	LoginStepAnswerSecurityQuestion                                      // 'AnswerSecurityQuestion'
	LoginStepOktaVerify                                                  // 'OktaVerify'
	LoginStepGoogleAuthenticatorInitialVerification                      // `GoogleAuthInitialVerify`
	LoginStepGoogleAuthenticatorConfirmation                             // `GoogleAuthConfirm`
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
	var steps []LoginStep
	if resp.CancelResponse != nil {
		steps = append(steps, LoginStepCancel)
	}
	_, err := resp.remediationOption("identify")
	if err == nil {
		steps = append(steps, LoginStepIdentify)
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
		steps = append(steps, LoginStepProviderIdentify)
	} else {
		r.identifyProviders = nil
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Email", false)
	if err == nil {
		steps = append(steps, LoginStepEmailVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Phone", false)
	if err == nil {
		steps = append(steps, LoginStepPhoneVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Security Question", false)
	if err == nil {
		steps = append(steps, LoginStepAnswerSecurityQuestion)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Okta Verify", false)
	if err == nil {
		steps = append(steps, LoginStepOktaVerify)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Google Authenticator", false)
	if err == nil {
		steps = append(steps, LoginStepGoogleAuthenticatorConfirmation)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Phone", false)
	if err == nil {
		steps = append(steps, LoginStepPhoneInitialVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Google Authenticator", false)
	if err == nil {
		steps = append(steps, LoginStepGoogleAuthenticatorInitialVerification)
	}
	ro, err := resp.remediationOption("reenroll-authenticator")
	if err == nil {
		v, _ := ro.value("credentials")
		if v != nil && v.Form != nil {
			for i := range v.Form.FormValues {
				if v.Form.FormValues[i].Label == "New password" {
					steps = append(steps, LoginStepSetupNewPassword)
				}
			}
		}
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		steps = append(steps, LoginStepSkip)
	}
	if len(steps) == 0 {
		return fmt.Errorf("there are no more steps available: %+v", resp.Messages.Values)
	}
	r.availableSteps = steps
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

func enrollGoogleAuth(ctx context.Context, handle *InteractionHandle) (*Response, error) {
	resp, err := idx.introspect(ctx, handle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Google Authenticator", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	return ro.proceed(ctx, authenticator)
}
