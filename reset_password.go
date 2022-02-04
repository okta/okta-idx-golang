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
)

type Credentials struct {
	Password string `json:"passcode"`
}

type IdentifyRequest struct {
	Identifier  string      `json:"identifier"`
	Credentials Credentials `json:"credentials"`
	RememberMe  bool        `json:"rememberMe"`
}

type ResetPasswordResponse struct {
	idxContext     *Context
	token          *Token
	availableSteps []ResetPasswordStep
	sq             *SecurityQuestion
}

// InitPasswordReset Initialize password reset.
func (c *Client) InitPasswordReset(ctx context.Context, ir *IdentifyRequest) (*ResetPasswordResponse, error) {
	idxContext, err := c.interact(ctx, nil)
	if err != nil {
		return nil, err
	}
	resp, err := identifyAndRecover(ctx, idxContext.InteractionHandle, ir)
	if err != nil {
		return nil, err
	}
	rpr := &ResetPasswordResponse{
		idxContext: idxContext,
	}
	err = rpr.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return rpr, nil
}

// Restart Restart password reset.
func (r *ResetPasswordResponse) Restart(ctx context.Context, ir *IdentifyRequest) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepRestart) {
		return r.missingStepError(ResetPasswordStepRestart)
	}
	resp, err := identifyAndRecover(ctx, r.idxContext.InteractionHandle, ir)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func identifyAndRecover(ctx context.Context, ih *InteractionHandle, ir *IdentifyRequest) (*Response, error) {
	resp, err := idx.introspect(ctx, ih)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticator != nil {
		resp, err = resp.CurrentAuthenticator.Value.Recover.proceed(ctx, nil)
		if err != nil {
			return nil, err
		}
		var ro *RemediationOption
		ro, err = resp.remediationOption("identify-recovery")
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(ir)
		resp, err = ro.proceed(ctx, b)
		if err != nil {
			return resp, err
		}
		return resp, nil
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
	return recoverProceed(ctx, resp)
}

func recoverProceed(ctx context.Context, resp *Response) (*Response, error) {
	if resp.CurrentAuthenticatorEnrollment != nil {
		return resp.CurrentAuthenticatorEnrollment.Value.Recover.proceed(ctx, nil)
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Password", true)
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
	if resp.CurrentAuthenticatorEnrollment == nil {
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' " +
			"field is missing from the response")
	}
	return resp.CurrentAuthenticatorEnrollment.Value.Recover.proceed(ctx, nil)
}

// VerifyEmail Verify email.
func (r *ResetPasswordResponse) VerifyEmail(ctx context.Context) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepEmailVerification) {
		return r.missingStepError(ResetPasswordStepEmailVerification)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	resp, err = recoverProceed(ctx, resp)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Email", true)
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
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.appendStep(ResetPasswordStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail Confirm email.
func (r *ResetPasswordResponse) ConfirmEmail(ctx context.Context, code string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepEmailConfirmation) {
		return r.missingStepError(ResetPasswordStepEmailConfirmation)
	}
	return r.confirmWithCode(ctx, code)
}

// AnswerSecurityQuestion Answer security question.
func (r *ResetPasswordResponse) AnswerSecurityQuestion(ctx context.Context, answer string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepAnswerSecurityQuestion) {
		return r.missingStepError(ResetPasswordStepAnswerSecurityQuestion)
	}
	resp, err := idx.introspect(ctx, r.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"%s": "%s",
					"answer": "%s"
				}
			}`, questionKey, r.sq.QuestionKey, answer))
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	defer func() { r.sq = nil }() // remove security question to avid confusion
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SetNewPassword Set new password.
func (r *ResetPasswordResponse) SetNewPassword(ctx context.Context, password string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepNewPassword) {
		return r.missingStepError(ResetPasswordStepNewPassword)
	}
	resp, err := setPassword(ctx, r.idxContext, "reset-authenticator", password)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Cancel the whole reset password process.
func (r *ResetPasswordResponse) Cancel(ctx context.Context) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepCancel) {
		return r.missingStepError(ResetPasswordStepCancel)
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
	r.appendStep(ResetPasswordStepRestart)
	return r, nil
}

// SecurityQuestion should return SecurityQuestion object in case there is step
// 'ANSWER SECURITY_QUESTION' present in the available steps. It will have
// non-empty 'questionKey' (unique identifier) and 'question' (human readable
// question) fields In case 'ANSWER SECURITY_QUESTION' is not in the list of
// available steps, response will be nil.
func (r *ResetPasswordResponse) SecurityQuestion() *SecurityQuestion {
	return r.sq
}

// AvailableSteps returns list of steps that can be executed next.  In case of
// successful authentication, list will contain only one "SUCCESS" step.
func (r *ResetPasswordResponse) AvailableSteps() []ResetPasswordStep {
	return r.availableSteps
}

// HasStep checks if the provided step is present in the list of available
// steps.
func (r *ResetPasswordResponse) HasStep(s ResetPasswordStep) bool {
	for i := range r.availableSteps {
		if r.availableSteps[i] == s {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true in case "SUCCESS"is present in the list of
// available steps.
func (r *ResetPasswordResponse) IsAuthenticated() bool {
	return r.HasStep(ResetPasswordStepSuccess)
}

// Token returns authorization token. This method should be called when there is
// "SUCCESS" step present in the list of available steps.
func (r *ResetPasswordResponse) Token() *Token {
	return r.token
}

type ResetPasswordStep int

// String String representation of ResetPasswordStep.
func (s ResetPasswordStep) String() string {
	v, ok := resetStepText[s]
	if ok {
		return v
	}
	return unknownStep
}

var resetStepText = map[ResetPasswordStep]string{
	ResetPasswordStepEmailVerification:      "EMAIL_VERIFICATION",
	ResetPasswordStepEmailConfirmation:      "EMAIL_CONFIRMATION",
	ResetPasswordStepAnswerSecurityQuestion: "ANSWER SECURITY_QUESTION",
	ResetPasswordStepNewPassword:            "NEW_PASSWORD",
	ResetPasswordStepCancel:                 "CANCEL",
	ResetPasswordStepRestart:                "RESTART",
	ResetPasswordStepSkip:                   "SKIP",
	ResetPasswordStepSuccess:                "SUCCESS",
}

// These codes indicate what method(s) can be called in the next step.
const (
	ResetPasswordStepEmailVerification      ResetPasswordStep = iota + 1 // 'VerifyEmail'
	ResetPasswordStepEmailConfirmation                                   // 'ConfirmEmail'
	ResetPasswordStepAnswerSecurityQuestion                              // 'AnswerSecurityQuestion'
	ResetPasswordStepNewPassword                                         // 'SetNewPassword'
	ResetPasswordStepCancel                                              // 'Cancel'
	ResetPasswordStepRestart                                             // 'Restart'
	ResetPasswordStepSkip                                                // 'Skip'
	ResetPasswordStepSuccess                                             // 'Token'
)

const (
	questionKey = "questionKey"
	unknownStep = "UNKNOWN"
)

// nolint
func (r *ResetPasswordResponse) setupNextSteps(ctx context.Context, resp *Response) error {
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
		// reset steps
		r.availableSteps = []ResetPasswordStep{ResetPasswordStepSuccess}
		return nil
	}

	// reset steps
	r.availableSteps = []ResetPasswordStep{}

	if resp.CancelResponse != nil {
		r.appendStep(ResetPasswordStepCancel)
	}
	_, _, err := resp.authenticatorOption("select-authenticator-authenticate", "Email", false)
	if err == nil {
		r.appendStep(ResetPasswordStepEmailVerification)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		r.appendStep(ResetPasswordStepSkip)
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err == nil {
	loop:
		for i := range ro.FormValues {
			if ro.FormValues[i].Form != nil && len(ro.FormValues[i].Form.FormValues) > 0 {
				for j := range ro.FormValues[i].Form.FormValues {
					if ro.FormValues[i].Form.FormValues[j].Name == questionKey {
						r.sq = &SecurityQuestion{
							QuestionKey: ro.FormValues[i].Form.FormValues[j].Value.String(),
							Question:    ro.FormValues[i].Form.FormValues[j].Label,
						}
						r.appendStep(ResetPasswordStepAnswerSecurityQuestion)
						break loop
					}
				}
			}
		}
	}
	ro, err = resp.remediationOption("reset-authenticator")
	if err == nil {
	loop2:
		for i := range ro.FormValues {
			if ro.FormValues[i].Form != nil && len(ro.FormValues[i].Form.FormValues) > 0 {
				for j := range ro.FormValues[i].Form.FormValues {
					if ro.FormValues[i].Form.FormValues[j].Label == "New password" {
						r.appendStep(ResetPasswordStepNewPassword)
						break loop2
					}
				}
			}
		}
	}
	if len(r.availableSteps) == 0 {
		return fmt.Errorf("there are no more steps available: %v", resp.Messages.Values)
	}
	return nil
}

func (r *ResetPasswordResponse) confirmWithCode(ctx context.Context, code string) (*ResetPasswordResponse, error) {
	resp, err := passcodeAuth(ctx, r.idxContext, "challenge-authenticator", code)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	return r, err
}

func (r *ResetPasswordResponse) missingStepError(missingStep ResetPasswordStep) (*ResetPasswordResponse, error) {
	steps := ""
	for index, step := range r.availableSteps {
		if index != 0 {
			steps = fmt.Sprintf("%s, ", steps)
		}
		steps = fmt.Sprintf("%s%q", steps, step)
	}
	return nil, fmt.Errorf("%q reset password step is not available, please try one of %s", missingStep, steps)
}

func (r *ResetPasswordResponse) appendStep(step ResetPasswordStep) {
	for _, _step := range r.availableSteps {
		if step == _step {
			return
		}
	}
	r.availableSteps = append(r.availableSteps, step)
}
