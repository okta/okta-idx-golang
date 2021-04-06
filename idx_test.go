// +build unit

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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var validYAMLConfig = `okta:
  idx:
    clientId: "foo"
    clientSecret: "bar"
    issuer: "https://okta.com"
    scopes:
      - "openid"
      - "profile"
    redirectUri: "https://okta.com"
`

func TestConfiguration(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		c := config{}
		v := viper.New()
		v.SetConfigType("yaml")
		err := v.ReadConfig(strings.NewReader(validYAMLConfig))
		require.NoError(t, err)
		err = v.Unmarshal(&c)
		require.NoError(t, err)
		err = c.Validate()
		assert.NoError(t, err)
	})
	t.Run("invalid_configuration", func(t *testing.T) {
		c := &config{}
		err := c.Validate()
		assert.Error(t, err)
	})
	t.Run("missing_client_id", func(t *testing.T) {
		c := config{}
		v := viper.New()
		v.SetConfigType("yaml")
		err := v.ReadConfig(strings.NewReader(validYAMLConfig))
		require.NoError(t, err)
		v.Set("okta.idx.clientId", "")
		err = v.Unmarshal(&c)
		require.NoError(t, err)
		err = c.Validate()
		assert.EqualError(t, err, "ClientID: cannot be blank.")
	})
}

func TestClient_Interact(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			assert.NoError(t, err)
			assert.Equal(t, "foo", r.PostForm.Get("client_id"))
			assert.Equal(t, []string{"openid profile"}, r.PostForm["scope"])
			_, err = w.Write([]byte(`{"interaction_handle":"abcd"}`))
			assert.NoError(t, err)
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Interact(context.TODO())
		assert.NoError(t, err)
	})
	t.Run("invalid_config_url", func(t *testing.T) {
		client := Client{
			config: testConfig("%$^@&@&^$"),
		}
		_, err := client.Interact(context.TODO())
		assert.EqualError(t, err, `failed to create interact http request: parse "%$^@&@&^$/v1/interact": invalid URL escape "%$^"`)
	})
	t.Run("http_client_error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Interact(context.TODO())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "http call has failed")
	})
	t.Run("invalid_response_body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`###`))
			assert.NoError(t, err)
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Interact(context.TODO())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal response body")
	})
	t.Run("bad_request", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{
    "version": "1.0.0",
    "messages": {
        "type": "array",
        "value": [
            {
                "message": "'stateHandle' is required.",
                "i18n": {
                    "key": "api.error.field_required",
                    "params": [
                        "stateHandle"
                    ]
                },
                "class": "ERROR"
            }
        ]
    }
}`))
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Interact(context.TODO())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `'stateHandle' is required.`)
	})
}

func TestClient_Introspect(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			var ih InteractionHandle
			err = json.Unmarshal(body, &ih)
			assert.NoError(t, err)
			assert.Equal(t, "abcd", ih.InteractionHandle)
			s := `{
    "remediation": {
        "type": "array",
        "value": [
            {
                "rel": [
                    "create-form"
                ],
                "name": "identify",
                "href": "https://example.com/idp/idx/identify",
                "method": "POST",
                "value": [
                    {
                        "name": "identifier",
                        "label": "Username"
                    },
                    {
                        "name": "credentials",
                        "type": "object",
                        "form": {
                            "value": [
                                {
                                    "name": "passcode",
                                    "label": "Password",
                                    "secret": true
                                }
                            ]
                        },
                        "required": true
                    },
                    {
                        "name": "rememberMe",
                        "type": "boolean",
                        "label": "Remember this device"
                    },
                    {
                        "name": "stateHandle",
                        "required": true,
                        "value": "efg",
                        "visible": false,
                        "mutable": false
                    }
                ],
                "accepts": "application/ion+json; okta-version=1.0.0"
            }
        ]
    },
    "cancel": {
        "rel": [
            "create-form"
        ],
        "name": "cancel",
        "href": "https://example.com/idp/idx/cancel",
        "method": "POST",
        "value": [
            {
                "name": "stateHandle",
                "required": true,
                "value": "efg",
                "visible": false,
                "mutable": false
            }
        ],
        "accepts": "application/ion+json; okta-version=1.0.0"
    }
}`
			_, err = w.Write([]byte(s))
			assert.NoError(t, err)
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		resp, err := client.Introspect(context.TODO(), &Context{interactionHandle: &InteractionHandle{"abcd"}})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Remediation.RemediationOptions))
		assert.Equal(t, 4, len(resp.Remediation.RemediationOptions[0].FormValues))
		assert.NotEmpty(t, resp.raw)
		for _, fm := range resp.Remediation.RemediationOptions[0].FormValues {
			if fm.Name == "credentials" {
				assert.Equal(t, "passcode", fm.Form.FormValues[0].Name)
			}
		}
	})
	t.Run("invalid_config_url", func(t *testing.T) {
		client := Client{
			config: testConfig("%$^@&@&^$"),
		}
		_, err := client.Introspect(context.TODO(), nil)
		assert.EqualError(t, err, `could not parse issuer: parse "%$^@&@&^$": invalid URL escape "%$^"`)
	})
	t.Run("http_client_error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Introspect(context.TODO(), &Context{interactionHandle: &InteractionHandle{"abcd"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "http call has failed")
	})
	t.Run("invalid_response_body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`###`))
			assert.NoError(t, err)
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Introspect(context.TODO(), &Context{interactionHandle: &InteractionHandle{"abcd"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal response body")
	})
	t.Run("unauthorized", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{
    "version": "1.0.0",
    "messages": {
        "type": "array",
        "value": [
            {
                "message": "The session has expired.",
                "i18n": {
                    "key": "idx.session.expired"
                },
                "class": "ERROR"
            }
        ]
    }
}`))
		}))
		defer ts.Close()
		client := Client{
			config:     testConfig(ts.URL),
			httpClient: ts.Client(),
		}
		_, err := client.Introspect(context.TODO(), &Context{interactionHandle: &InteractionHandle{"abcd"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `The session has expired.`)
	})
}

func testConfig(url string) *config {
	return &config{
		Okta: struct {
			IDX struct {
				ClientID     string   `mapstructure:"clientId" schema:"client_id"`
				ClientSecret string   `mapstructure:"clientSecret" schema:"client_secret"`
				Issuer       string   `mapstructure:"issuer" schema:"-"`
				Scopes       []string `mapstructure:"scopes" schema:"scope"`
				RedirectURI  string   `mapstructure:"redirectUri" schema:"redirect_uri"`
			} `mapstructure:"idx"`
		}{
			IDX: struct {
				ClientID     string   `mapstructure:"clientId" schema:"client_id"`
				ClientSecret string   `mapstructure:"clientSecret" schema:"client_secret"`
				Issuer       string   `mapstructure:"issuer" schema:"-"`
				Scopes       []string `mapstructure:"scopes" schema:"scope"`
				RedirectURI  string   `mapstructure:"redirectUri" schema:"redirect_uri"`
			}{
				ClientID:     "foo",
				ClientSecret: "bar",
				Issuer:       url,
				Scopes:       []string{"openid", "profile"},
				RedirectURI:  url,
			},
		},
	}
}
