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

import (
	"context"
	"fmt"
	"strconv"
)

type Identity struct {
	Identifier string
	Passcode   string
	RememberMe bool
}

func (c *Client) Authenticate(ctx context.Context, identity Identity) (*Token, error) {
	idxContext, err := c.Interact(ctx, nil)
	if err != nil {
		return nil, err
	}

	response, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}

	remediationOption, err := response.getRemediationOption("identify")
	if err != nil {
		return nil, err
	}

	singleStepIdentity := remediationOption.formHas("credentials")

	if singleStepIdentity == true {
		response, err = handleSingleStepIdentity(ctx, &identity, remediationOption)
		if err != nil {
			return nil, err
		}

	} else {
		response, err = handleIdentityFirst(ctx, &identity, remediationOption)
		if err != nil {
			return nil, err
		}
	}

	if !response.LoginSuccess() {
		return nil, fmt.Errorf("could not authenticate you. We got stuck somewhere with a remediation of:\n%v\n", response)
	}

	exchangeForm := []byte(`{
		"client_secret": "` + c.ClientSecret() + `",
		"code_verifier": "` + idxContext.CodeVerifier() + `"
	}`)

	tokens, err := response.SuccessResponse.ExchangeCode(context.Background(), exchangeForm)
	if err != nil {
		return nil, err
	}

	return tokens, nil

}

func handleSingleStepIdentity(ctx context.Context, identity *Identity, remediationOption *RemediationOption) (*Response, error) {
	identify := []byte(`{
		"identifier": "` + identity.Identifier + `",
		"credentials": {
			"passcode": "` + identity.Passcode + `"
		},
		"rememberMe": "` + strconv.FormatBool(identity.RememberMe) + `"
	}`)

	return remediationOption.Proceed(context.TODO(), identify)
}

func handleIdentityFirst(ctx context.Context, identity *Identity, remediationOption *RemediationOption) (*Response, error) {
	identify := []byte(`{
		"identifier": "` + identity.Identifier + `",
		"rememberMe": "` + strconv.FormatBool(identity.RememberMe) + `"
	}`)

	response, err := remediationOption.Proceed(context.TODO(), identify)
	if err != nil {
		return nil, err
	}

	remediationOption, err = response.getRemediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}

	credentials := []byte(`{
		"credentials": {
			"passcode": "` + identity.Passcode + `"
		}
	}`)

	return remediationOption.Proceed(context.TODO(), credentials)
}

func (r *Response) getRemediationOption(optionName string) (*RemediationOption, error) {
	for _, option := range r.Remediation.RemediationOptions {
		if option.Name == optionName {
			return &option, nil
		}
	}

	return nil, fmt.Errorf("could not locate a remediation option with the name '%s'\n", optionName)
}

func (o *RemediationOption) formHas(val string) bool {
	for _, formval := range o.FormValues {
		if formval.Name == val {
			return true
		}
	}

	return false
}
