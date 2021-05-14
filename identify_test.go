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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_InitLogin(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			ih := make(map[string]interface{})
			err = json.Unmarshal(body, &ih)
			assert.NoError(t, err)
			var s string
			switch ih["interactionHandle"].(string) {
			case "a":
				s = fmt.Sprintf(`{
			    "stateHandle": "a",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "identify",
			                "href": "http://%s/idp/idx/identify",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "identifier",
			                        "label": "Username"
			                    },
			                    {
			                        "name": "rememberMe",
			                        "type": "boolean",
			                        "label": "Remember this device"
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "a",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "a",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host)
			case "b":
				s = fmt.Sprintf(`{
			    "stateHandle": "b",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "challenge-authenticator",
			                "relatesTo": [
			                    "$.currentAuthenticatorEnrollment"
			                ],
			                "href": "http://%s/idp/idx/challenge/answer",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
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
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "b",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            },
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "select-authenticator-authenticate",
			                "href": "http://%s/idp/idx/challenge",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "authenticator",
			                        "type": "object",
			                        "options": [
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3e9k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[0]"
			                            },
			                            {
			                                "label": "Password",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hwe8llr6CyxE5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "required": false,
			                                                "value": "password",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[1]"
			                            }
			                        ]
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "b",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "b",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host, r.Host)
			case "c":
				{
					s = fmt.Sprintf(`{
			    "stateHandle": "c",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "select-authenticator-authenticate",
			                "href": "http://%s/idp/idx/challenge",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "authenticator",
			                        "type": "object",
			                        "options": [
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "butl3e8k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[0]"
			                            }
			                        ]
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "c",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "c",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host)
				}
			default:
				s = fmt.Sprintf(`{
			    "stateHandle": "a",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "identify",
			                "href": "http://%s/idp/idx/identify",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "identifier",
			                        "label": "Username"
			                    },
			                    {
			                        "name": "rememberMe",
			                        "type": "boolean",
			                        "label": "Remember this device"
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "a",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "a",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host)
			}
			w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/identify", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "stateHandle": "b",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "challenge-authenticator",
			                "relatesTo": [
			                    "$.currentAuthenticatorEnrollment"
			                ],
			                "href": "http://%s/idp/idx/challenge/answer",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
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
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "b",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            },
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "select-authenticator-authenticate",
			                "href": "http://%s/idp/idx/challenge",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "authenticator",
			                        "type": "object",
			                        "options": [
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3e9k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[0]"
			                            },
			                            {
			                                "label": "Password",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hwe8llr6CyxE5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "required": false,
			                                                "value": "password",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[1]"
			                            }
			                        ]
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "b",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "b",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host, r.Host)
			w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/challenge/answer", func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			ih := make(map[string]interface{})
			err = json.Unmarshal(body, &ih)
			assert.NoError(t, err)
			assert.Equal(t, "qwerty", ih["credentials"].(map[string]interface{})["passcode"])

			s := fmt.Sprintf(`{
			    "stateHandle": "c",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "select-authenticator-authenticate",
			                "href": "http://%s/idp/idx/challenge",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "value": [
			                    {
			                        "name": "authenticator",
			                        "type": "object",
			                        "options": [
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "butl3e8k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[0]"
			                            }
			                        ]
			                    },
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "c",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "c",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host)

			w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/challenge", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "stateHandle": "d",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "challenge-poll",
			                "relatesTo": [
			                    "$.currentAuthenticator"
			                ],
			                "href": "http://%s/idp/idx/authenticators/poll",
			                "method": "POST",
			                "produces": "application/ion+json; okta-version=1.0.0",
			                "refresh": 4000,
			                "value": [
			                    {
			                        "name": "stateHandle",
			                        "required": true,
			                        "value": "d",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            }
			        ]
			    },
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "d",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    }
			}`, r.Host, r.Host)
			w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/authenticators/poll", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "stateHandle": "e",
			    "cancel": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "cancel",
			        "href": "http://%s/idp/idx/cancel",
			        "method": "POST",
			        "produces": "application/ion+json; okta-version=1.0.0",
			        "value": [
			            {
			                "name": "stateHandle",
			                "required": true,
			                "value": "e",
			                "visible": false,
			                "mutable": false
			            }
			        ],
			        "accepts": "application/json; okta-version=1.0.0"
			    },
			    "successWithInteractionCode": {
			        "rel": [
			            "create-form"
			        ],
			        "name": "issue",
			        "href": "http://%s/oauth2/ausl0y235gvGoRoyH5d6/v1/token",
			        "method": "POST",
			        "value": [
			            {
			                "name": "grant_type",
			                "required": true,
			                "value": "interaction_code"
			            },
			            {
			                "name": "interaction_code",
			                "required": true,
			                "value": "big_random_string"
			            },
			            {
			                "name": "client_id",
			                "required": true,
			                "value": "foo"
			            },
			            {
			                "name": "client_secret",
			                "required": true
			            },
			            {
			                "name": "code_verifier",
			                "required": true
			            }
			        ],
			        "accepts": "application/x-www-form-urlencoded"
			    }
			}`, r.Host, r.Host)
			w.Write([]byte(s))
		})
		mux.HandleFunc("/oauth2/ausl0y235gvGoRoyH5d6/v1/token", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{
			    "token_type": "Bearer",
			    "expires_in": 3600,
			    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			    "scope": "openid profile",
			    "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
			}`))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		client, err := NewClient(
			WithClientID("foo"),
			WithClientSecret("bar"),
			WithIssuer(ts.URL),
			WithScopes([]string{"openid", "profile"}),
			WithRedirectURI(ts.URL+"/authorization-code/callback"))
		require.NoError(t, err)
		require.NotNil(t, client)
		client = client.WithHTTPClient(ts.Client())

		resp, err := client.InitLogin(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepCancel)
		require.Contains(t, resp.AvailableSteps(), LoginStepIdentify)

		up := &IdentifyRequest{
			Identifier: "test.user@okta.com",
		}
		resp, err = resp.Identify(context.TODO(), up)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepCancel)
		require.Contains(t, resp.AvailableSteps(), LoginStepPassword)
		require.Contains(t, resp.AvailableSteps(), LoginStepOktaVerify)

		resp, err = resp.Password(context.TODO(), "qwerty")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepCancel)
		require.Contains(t, resp.AvailableSteps(), LoginStepOktaVerify)

		resp, err = resp.OktaVerify(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepSuccess)
	})
}
