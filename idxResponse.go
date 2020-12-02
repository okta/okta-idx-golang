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
	"context"
	"encoding/json"
	"io/ioutil"
	"time"
)

type IDXResponse struct {
	StateHandle string    `json:"stateHandle"`
	Version     string    `json:"version"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Intent      string    `json:"intent"`
	CancelObj   IonObject `json:"cancel"`
	raw         []byte
}

func (idxr *IDXResponse) Remediation() error {
	return nil
}

func (idxr *IDXResponse) Cancel(ctx context.Context) (*IDXResponse, error) {
	generalRequest := &GeneralRequest{
		"stateHandle": idxr.CancelObj.Value[0].Value,
		"method":      idxr.CancelObj.Method,
		"href":        idxr.CancelObj.Href,
	}

	req, err := generalRequest.NewRequest(ctx, &IDXC)
	if err != nil {
		return nil, err
	}

	resp, err := IDXC.requestExecutor.GetHttpClient().Do(req)
	if err != nil {
		return nil, err
	}

	idxResp := &IDXResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, idxResp)
	if err != nil {
		return nil, err
	}

	return idxResp, nil
}

func (idxr *IDXResponse) SuccessWithInteractionCode() error {
	return nil
}

func (idxr *IDXResponse) LoginSuccess() bool {
	return false
}

func (idxr *IDXResponse) Raw() []byte {
	return idxr.raw
}

func (idxr *IDXResponse) UnmarshalJSON(data []byte) error {
	type Alias IDXResponse

	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(idxr),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	idxr.raw = data

	return nil
}
