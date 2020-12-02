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

import "encoding/json"

type FormValue struct {
	Name      string        `json:"name"`
	Label     string        `json:"label"`
	Type      string        `json:"type"`
	Value     []interface{} `json:"value"`
	Visible   bool          `json:"visible"`
	Mutable   bool          `json:"mutable"`
	Required  bool          `json:"required"`
	Secret    bool          `json:"secret"`
	relatesTo []byte        `json:"relatesTo"`
}

func (fv *FormValue) RelatesTo() ([]byte, error) {
	return nil, nil
}

func (fv *FormValue) Form() ([]FormValue, error) {
	return nil, nil
}

func (fv *FormValue) Options() ([]FormValue, error) {
	return nil, nil
}

func (fv *FormValue) UnmarshalJSON(data []byte) error {
	type Alias FormValue

	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(fv),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	fv.relatesTo = data

	return nil
}
