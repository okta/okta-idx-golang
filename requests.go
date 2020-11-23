/**
 * Copyright 2017 - Present Okta, Inc.
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

package oktaIdentityEngine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

type IntrospectRequest struct {
	InteractionHandle string `json:"interactionHandle"`
}

func (ir *IntrospectRequest) Marshal() ([]byte, error) {
	return json.Marshal(ir)
}

func (ir *IntrospectRequest) NewRequest(ctx context.Context, oie *OktaIdentityEngineClient) (*http.Request, error) {
	domain, err := url.Parse(oie.config.Okta.Client.OIE.Issuer)
	if err != nil {
		return nil, errors.New("could not parse your issuer")
	}

	req, err := oie.
		requestExecutor.
		NewRequest(
			http.MethodPost,
			domain.Scheme+"://"+domain.Host+"/idp/idx/introspect",
			ir,
		)

	req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/ion+json; okta-version=1.0.0")
	req.Header.Add("Accept", "application/ion+json; okta-version=1.0.0")

	return req, err
}

type InteractRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope"`
}

func (ir *InteractRequest) Marshal() ([]byte, error) {
	interactRequest := url.Values{}
	interactRequest.Set("client_id", ir.ClientId)
	interactRequest.Set("client_secret", ir.ClientSecret)
	interactRequest.Set("scope", ir.Scope)
	return []byte(interactRequest.Encode()), nil
}

func (ir *InteractRequest) NewRequest(ctx context.Context, oie *OktaIdentityEngineClient) (*http.Request, error) {
	req, err := oie.
		requestExecutor.
		NewRequest(
			http.MethodPost,
			oie.config.Okta.Client.OIE.Issuer+"/v1/interact",
			ir,
		)

	req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return req, err
}
