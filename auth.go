/**
 * Copyright 2020 - Present Okta, Inc.
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

import "context"

// Auth Status Constants
const (
	AuthStatusSuccess         = "SUCCESS"
	AuthStatusPasswordExpired = "PASSWORD_EXPIRED"
	AuthStatusUnhandled       = "UNHANDLED_RESPONSE"
)

type AuthenticationOptions struct {
	Username string
	Password string
}

type ChangePasswordOptions struct {
	OldPassword string
	NewPassword string
}

type AuthenticationResponse struct {
	idxContext           *Context
	token                *Token
	authenticationStatus string
}

func (ar *AuthenticationResponse) AuthenticationStatus() string {
	return ar.authenticationStatus
}

func (ar *AuthenticationResponse) Token() *Token {
	return ar.token
}

func (ar *AuthenticationResponse) IdxContext() *Context {
	return ar.idxContext
}

func (c *Client) Authenticate(ctx context.Context, options AuthenticationOptions) (*AuthenticationResponse, error) {
	var authenticationResponse AuthenticationResponse

	idxContext, err := c.Interact(ctx)
	if err != nil {
		return nil, err
	}
	authenticationResponse.idxContext = idxContext

	response, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}

	remediationOption, err := response.remediationOption("identify")
	if err != nil {
		return nil, err
	}

	identityFirst, err := remediationOption.IsIdentityFirst()
	if err != nil {
		return nil, err
	}

	if identityFirst {
		response, err := c.handleIdentityFirst(ctx, options, remediationOption)
		if err != nil {
			return nil, err
		}

		return c.handleRemediation(ctx, idxContext, response)
	}

	return nil, nil
}

func (c *Client) handleRemediation(ctx context.Context, idxContext *Context, response *Response) (*AuthenticationResponse, error) {
	authenticationResponse := &AuthenticationResponse{
		idxContext:           idxContext,
		authenticationStatus: AuthStatusUnhandled,
	}

	if response.LoginSuccess() {
		exchangeForm := []byte(`{
			"client_secret": "` + c.ClientSecret() + `",
			"code_verifier": "` + idxContext.CodeVerifier() + `"
		}`)

		tokens, err := response.SuccessResponse.ExchangeCode(ctx, exchangeForm)
		if err != nil {
			return nil, err
		}
		authenticationResponse.token = tokens
		authenticationResponse.authenticationStatus = AuthStatusSuccess

		return authenticationResponse, nil
	}

	_, err := response.remediationOption("reenroll-authenticator")
	if err == nil {
		// We have a reenroll-authenticator remediation option
		authenticationResponse.authenticationStatus = AuthStatusPasswordExpired
		return authenticationResponse, nil
	}

	return authenticationResponse, nil
}

func (c *Client) ChangePassword(ctx context.Context, idxContext *Context, options ChangePasswordOptions) (*AuthenticationResponse, error) {
	creds := []byte(`{
		"credentials": {
			"passcode": "` + options.NewPassword + `"
		}
	}`)
	response, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}

	remediationOption, err := response.remediationOption("reenroll-authenticator")
	if err != nil {
		return nil, err
	}

	resp, err := remediationOption.Proceed(ctx, creds)
	if err != nil {
		return nil, err
	}

	return c.handleRemediation(ctx, idxContext, resp)
}

func (c *Client) handleIdentityFirst(ctx context.Context, options AuthenticationOptions, remediationOption *RemediationOption) (*Response, error) {
	identify := []byte(`{
		"identifier": "` + options.Username + `"
	}`)

	response, err := remediationOption.Proceed(ctx, identify)
	if err != nil {
		return nil, err
	}

	remediationOption, err = response.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}

	credentials := []byte(`{
		"credentials": {
			"passcode": "` + options.Password + `"
		}
	}`)

	return remediationOption.Proceed(ctx, credentials)
}

// nolint
func (c *Client) handleSingleStepIdentity(ctx context.Context, ao AuthenticationOptions, ro *RemediationOption) (*Response, error) {
	identify := []byte(`{
		"identifier": "` + ao.Username + `",
		"credentials": {
			"passcode": "` + ao.Password + `"
		}
	}`)
	return ro.Proceed(ctx, identify)
}
