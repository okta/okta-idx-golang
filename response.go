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
	"net/http"

	"github.com/okta/okta-idx-golang/oktahttp"
	"github.com/pkg/errors"
)

type Response struct {
	StateHandle     string         `json:"stateHandle"`
	Version         string         `json:"version"`
	ExpiresAt       string         `json:"expiresAt"`
	Intent          string         `json:"intent"`
	Remediation     *Remediation   `json:"remediation"`
	CancelResponse  *Option        `json:"cancel"`
	SuccessResponse *SuccessOption `json:"successWithInteractionCode"`
	raw             []byte
}

func (r *Response) UnmarshalJSON(data []byte) error {
	type localIDX Response
	if err := json.Unmarshal(data, (*localIDX)(r)); err != nil {
		return err
	}
	r.raw = data
	return nil
}

// The method to call when you want to cancel the Okta Identity Engine flow.
// This will return a response for the first step
func (r *Response) Cancel(ctx context.Context) (*Response, error) {
	if r.CancelResponse == nil || len(r.CancelResponse.FormValues) == 0 {
		return nil, errors.New("valid cancel is missing from idx response")
	}
	m := make(map[string]interface{})
	for _, v := range r.CancelResponse.FormValues {
		m[v.Name] = v.Value
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cancel request: %v", err)
	}
	req, err := http.NewRequest(r.CancelResponse.Method, r.CancelResponse.Href, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create cancel request: %v", err)
	}
	req.Header.Set("Accepts", r.CancelResponse.Accepts)
	req.Header.Set("Content-Type", r.CancelResponse.Accepts)
	oktahttp.WithOktaUserAgent(req, packageVersion)
	req = req.WithContext(ctx)
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

// Returns the raw JSON body of the Okta Identity Engine response.
func (r *Response) Raw() []byte {
	return r.raw
}

// Check for the status of `successWithInteractionCode` indicating if the login was successful.
func (r *Response) LoginSuccess() bool {
	return r.SuccessResponse != nil
}
