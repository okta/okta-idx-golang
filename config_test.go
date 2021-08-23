// +build unit

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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_ConfigFromEnvVars(t *testing.T) {
	envVars := []struct {
		envName  string
		envValue string
		oldValue string
	}{
		{envName: "OKTA_IDX_ISSUER", envValue: "issuer"},
		{envName: "OKTA_IDX_CLIENTID", envValue: "clientid"},
		{envName: "OKTA_IDX_CLIENTSECRET", envValue: "clientsecret"},
		{envName: "OKTA_IDX_SCOPES", envValue: "openid,profile"},
		{envName: "OKTA_IDX_REDIRECTURI", envValue: "redirecturi"},
	}

	for _, envVar := range envVars {
		envVar.oldValue = os.Getenv(envVar.envName)
		os.Setenv(envVar.envName, envVar.envValue)
	}

	_, err := NewClient()
	require.NoError(t, err)

	for _, envVar := range envVars {
		if envVar.oldValue == "" {
			os.Unsetenv(envVar.envName)
			continue
		}
		os.Setenv(envVar.envName, envVar.oldValue)
	}
}
