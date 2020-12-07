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

package idx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/okta/okta-idx-golang/oktahttp"
	"github.com/pkg/errors"
)

type Remediation struct {
	Type               string              `json:"type"`
	RemediationOptions []RemediationOption `json:"value"`
}

type Token struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	IDToken     string `json:"idToken"`
	Scope       string `json:"scope"`
	TokenType   string `json:"tokenType"`
}

// Allow you to continue the remediation with this option.
type Option struct {
	Rel        []string    `json:"rel"`
	Name       string      `json:"name"`
	Href       string      `json:"href"`
	Method     string      `json:"method"`
	FormValues []FormValue `json:"value"`
	Accepts    string      `json:"accepts"`
}

// Form gets all form values
func (o *Option) Form() []FormValue {
	if o == nil {
		return nil
	}
	return o.FormValues
}

type FormValue struct {
	Name     string  `json:"name"`
	Label    string  `json:"label,omitempty"`
	Type     string  `json:"type,omitempty"`
	Value    *string `json:"value,omitempty"`
	Required *bool   `json:"required,omitempty"`
	Visible  *bool   `json:"visible,omitempty"`
	Mutable  *bool   `json:"mutable,omitempty"`
	Secret   *bool   `json:"secret,omitempty"`
	Form     *Form   `json:"form,omitempty"`
}

type Form struct {
	FormValues []FormValue `json:"value"`
}

type RemediationOption Option

// Form gets all form values
func (o *RemediationOption) Form() []FormValue {
	if o == nil {
		return nil
	}
	return o.FormValues
}

// Proceed allows you to continue the remediation with this option.
// It will return error when provided data does not contain all required data for the proceed call.
func (o *RemediationOption) Proceed(ctx context.Context, data []byte) (*Response, error) {
	if o == nil || len(o.FormValues) == 0 {
		return nil, errors.New("valid proceed is missing from idx response")
	}
	input := make(map[string]interface{})
	err := json.Unmarshal(data, &input)
	if err != nil {
		return nil, fmt.Errorf("failed to input data: %v", err)
	}
	output, err := form(input, nil, o.FormValues...)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(&output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proceed request: %v", err)
	}
	req, err := http.NewRequest(o.Method, o.Href, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create cancel request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accepts", o.Accepts)
	req.Header.Set("Content-Type", o.Accepts)
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := idx.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %v", err)
	}
	var idxResponse Response
	err = unmarshalResponse(resp, &idxResponse)
	if err != nil {
		return nil, err
	}
	return &idxResponse, nil
}

// nolint:gocyclo
func form(input, output map[string]interface{}, f ...FormValue) (map[string]interface{}, error) {
	if output == nil {
		output = make(map[string]interface{})
	}
	for _, v := range f {
		switch {
		case v.Value != nil:
			output[v.Name] = v.Value
		case v.Value == nil && v.Form == nil:
			vv, ok := input[v.Name]
			if !ok {
				return nil, fmt.Errorf("missing %s property from input", v.Name)
			}
			output[v.Name] = vv
		case v.Form != nil && len(v.Form.FormValues) != 0:
			vv, ok := input[v.Name]
			if !ok {
				return nil, fmt.Errorf("missing %s property from input", v.Name)
			}
			im, ok := vv.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s should be of type map[string]interface{}, got: %T", v.Name, vv)
			}
			var err error
			output[v.Name] = map[string]interface{}{}
			output[v.Name], err = form(im, output[v.Name].(map[string]interface{}), v.Form.FormValues...)
			if err != nil {
				return nil, err
			}
		}
	}
	return output, nil
}

type SuccessOption Option

// Exchange the code from SuccessWithInteractionCode
func (o *SuccessOption) ExchangeCode(ctx context.Context) (*Token, error) {
	if o == nil {
		return nil, errors.New("valid success response is missing from idx response")
	}
	output, err := form(map[string]interface{}{}, nil, o.FormValues...)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if strings.Contains(o.Accepts, "x-www-form-urlencoded") {
		data := url.Values{}
		for k, v := range output {
			data[k] = []string{*v.(*string)}
		}
		body = strings.NewReader(data.Encode())
	} else {
		b, _ := json.Marshal(&output)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(o.Method, o.Href, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create interact http request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accepts", o.Accepts)
	req.Header.Set("Content-Type", o.Accepts)
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := idx.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %v", err)
	}
	var token Token
	err = unmarshalResponse(resp, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}
