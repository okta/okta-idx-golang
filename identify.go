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
	"strings"
)

func (r *Response) Identify(ctx context.Context, ir *IdentifyRequest) (*Response, error) {
	ro, err := r.remediationOption("identify")
	if err != nil {
		return nil, err
	}
	identify := []byte(fmt.Sprintf(`{
                "identifier": "%s",
                "rememberMe": %t
            }`, ir.Identifier, ir.RememberMe))
	return ro.Proceed(ctx, identify)
}

func (r *Response) SetPasswordOnLogin(ctx context.Context, password string) (*Response, error) {
	ro, err := r.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(`{
				"credentials": {
					"passcode": "` + strings.TrimSpace(password) + `"
				}
			}`)
	return ro.Proceed(ctx, credentials)
}
