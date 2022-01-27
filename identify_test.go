//go:build unit
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
	var call, challangeCall int
	t.Run("happy_path", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch call {
			case 0:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "b",
				    "expiresAt": "2021-05-31T19:37:08.000Z",
				    "intent": "LOGIN",
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
				                "name": "select-enroll-profile",
				                "href": "http://%s/idp/idx/enroll",
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
				            },
				            {
				                "name": "redirect-idp",
				                "type": "FACEBOOK",
				                "idp": {
				                    "id": "0oasglqxggRrCMQAW5d6",
				                    "name": "Facebook IdP"
				                },
				                "href": "http://%s/oauth2/ausl0y235gvIoRoyH5d6/v1/authorize?client_id=0oal6ssroFGvEU0Oe5d6&request_uri=urn:okta:VWd4bEg1ellmd2lzRWctYVZoT1lXcFloeHdZT1NIdnd0VUlpeko2N21KSTowb2FzZ2xxeGdnUnJDTVFBVzVkNg",
				                "method": "GET"
				            },
				            {
				                "name": "redirect-idp",
				                "type": "GOOGLE",
				                "idp": {
				                    "id": "0oasgv6yj2ZQrW9fF5d6",
				                    "name": "Google IdP"
				                },
				                "href": "http://%s/oauth2/ausl0y235gvIoRoyH5d6/v1/authorize?client_id=0oal6ssroFGvEU0Oe5d6&request_uri=urn:okta:VWd4bEg1ellmd2lzRWctYVZoT1lXcFloeHdZT1NIdnd0VUlpeko2N21KSTowb2FzZ3Y2eWoyWlFyVzlmRjVkNg",
				                "method": "GET"
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal6ssroFGvEU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 1:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "b",
				    "expiresAt": "2021-05-31T19:37:08.000Z",
				    "intent": "LOGIN",
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
				                "name": "select-enroll-profile",
				                "href": "http://%s/idp/idx/enroll",
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
				            },
				            {
				                "name": "redirect-idp",
				                "type": "FACEBOOK",
				                "idp": {
				                    "id": "0oasglqxggRrCMQAW5d6",
				                    "name": "Facebook IdP"
				                },
				                "href": "http://%s/oauth2/ausl0y235gvIoRoyH5d6/v1/authorize?client_id=0oal6ssroFGvEU0Oe5d6&request_uri=urn:okta:VWd4bEg1ellmd2lzRWctYVZoT1lXcFloeHdZT1NIdnd0VUlpeko2N21KSTowb2FzZ2xxeGdnUnJDTVFBVzVkNg",
				                "method": "GET"
				            },
				            {
				                "name": "redirect-idp",
				                "type": "GOOGLE",
				                "idp": {
				                    "id": "0oasgv6yj2ZQrW9fF5d6",
				                    "name": "Google IdP"
				                },
				                "href": "http://%s/oauth2/ausl0y235gvIoRoyH5d6/v1/authorize?client_id=0oal6ssroFGvEU0Oe5d6&request_uri=urn:okta:VWd4bEg1ellmd2lzRWctYVZoT1lXcFloeHdZT1NIdnd0VUlpeko2N21KSTowb2FzZ3Y2eWoyWlFyVzlmRjVkNg",
				                "method": "GET"
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal6ssroFGvEU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 2:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "b",
				    "expiresAt": "2021-05-31T18:01:23.000Z",
				    "intent": "LOGIN",
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
				                                "label": "Email",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hwe9EdtbCyKV5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "email",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticatorEnrollments.value[0]"
				                            },
				                            {
				                                "label": "Okta Verify",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "Enter a code",
				                                                        "value": "totp"
				                                                    },
				                                                    {
				                                                        "label": "Get a push notification",
				                                                        "value": "push"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            },
				                            {
				                                "label": "Phone",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweaZ3zGU63b5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            },
				                                            {
				                                                "name": "enrollmentId",
				                                                "required": true,
				                                                "value": "paetnceczcDZduYCL5d6",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticatorEnrollments.value[2]"
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
				    "authenticators": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "autl3hwe9EdtbCyKV5d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "app",
				                "key": "okta_verify",
				                "id": "autl3e8k3bkOVrHAo5d6",
				                "displayName": "Okta Verify",
				                "methods": [
				                    {
				                        "type": "push"
				                    },
				                    {
				                        "type": "totp"
				                    }
				                ]
				            },
				            {
				                "type": "phone",
				                "key": "phone_number",
				                "id": "autl3hweaZ3zGU63b5d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "profile": {
				                    "email": "b***x@okta.com"
				                },
				                "type": "email",
				                "key": "okta_email",
				                "id": "eael2v03sTTXEN7KW5d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "profile": {
				                    "deviceName": "OnePlus 5T"
				                },
				                "type": "app",
				                "key": "okta_verify",
				                "id": "pfdo31uccd05gLgmN5d6",
				                "displayName": "Okta Verify",
				                "methods": [
				                    {
				                        "type": "push"
				                    },
				                    {
				                        "type": "totp"
				                    }
				                ]
				            },
				            {
				                "profile": {
				                    "phoneNumber": "+1 XXX-XXX-3693"
				                },
				                "type": "phone",
				                "key": "phone_number",
				                "id": "paetnceczcDZduYCL5d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00ul0y27xJNbFnsRy5d6"
				        }
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal6ssroFGvEU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/identify", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "version": "1.0.0",
			    "stateHandle": "b",
			    "expiresAt": "2021-05-31T17:42:10.000Z",
			    "intent": "LOGIN",
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
			                                "label": "Email",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hwe9EdtbCyKV5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "required": false,
			                                                "value": "email",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[0]"
			                            },
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3e8k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Enter a code",
			                                                        "value": "totp"
			                                                    },
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[1]"
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
			                                "relatesTo": "$.authenticatorEnrollments.value[2]"
			                            },
			                            {
			                                "label": "Phone",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hweaZ3zGU63b5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "SMS",
			                                                        "value": "sms"
			                                                    }
			                                                ]
			                                            },
			                                            {
			                                                "name": "enrollmentId",
			                                                "required": true,
			                                                "value": "paetnceczcDZduYCL5d6",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[3]"
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
			    "authenticators": {
			        "type": "array",
			        "value": [
			            {
			                "type": "email",
			                "key": "okta_email",
			                "id": "autl3hwe9EdtbCyKV5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "type": "app",
			                "key": "okta_verify",
			                "id": "autl3e8k3bkOVrHAo5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "type": "password",
			                "key": "okta_password",
			                "id": "autl3hwe8llr6CyxE5d6",
			                "displayName": "Password",
			                "methods": [
			                    {
			                        "type": "password"
			                    }
			                ]
			            },
			            {
			                "type": "phone",
			                "key": "phone_number",
			                "id": "autl3hweaZ3zGU63b5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "authenticatorEnrollments": {
			        "type": "array",
			        "value": [
			            {
			                "profile": {
			                    "email": "b***x@okta.com"
			                },
			                "type": "email",
			                "key": "okta_email",
			                "id": "eael2v03sTTXEN7KW5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "deviceName": "OnePlus 5T"
			                },
			                "type": "app",
			                "key": "okta_verify",
			                "id": "pfdo31uccd05gLgmN5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "type": "password",
			                "key": "okta_password",
			                "id": "lae1bm7l17eiudHus5d6",
			                "displayName": "Password",
			                "methods": [
			                    {
			                        "type": "password"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "phoneNumber": "+1 XXX-XXX-3693"
			                },
			                "type": "phone",
			                "key": "phone_number",
			                "id": "paetnceczcDZduYCL5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "user": {
			        "type": "object",
			        "value": {
			            "id": "00ul0y27xJNbFnsRy5d6"
			        }
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
			    },
			    "app": {
			        "type": "object",
			        "value": {
			            "name": "oidc_client",
			            "label": "My Web App",
			            "id": "0oal6ssroFGvEU0Oe5d6"
			        }
			    }
			}`, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
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
			    "version": "1.0.0",
			    "stateHandle": "b",
			    "expiresAt": "2021-05-31T17:42:11.000Z",
			    "intent": "LOGIN",
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
			                                "label": "Email",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hwe9EdtbCyKV5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "required": false,
			                                                "value": "email",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[0]"
			                            },
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3e8k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Enter a code",
			                                                        "value": "totp"
			                                                    },
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[1]"
			                            },
			                            {
			                                "label": "Phone",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hweaZ3zGU63b5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "SMS",
			                                                        "value": "sms"
			                                                    }
			                                                ]
			                                            },
			                                            {
			                                                "name": "enrollmentId",
			                                                "required": true,
			                                                "value": "paetnceczcDZduYCL5d6",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[2]"
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
			    "authenticators": {
			        "type": "array",
			        "value": [
			            {
			                "type": "email",
			                "key": "okta_email",
			                "id": "autl3hwe9EdtbCyKV5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "type": "app",
			                "key": "okta_verify",
			                "id": "autl3e8k3bkOVrHAo5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "type": "phone",
			                "key": "phone_number",
			                "id": "autl3hweaZ3zGU63b5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "authenticatorEnrollments": {
			        "type": "array",
			        "value": [
			            {
			                "profile": {
			                    "email": "b***x@okta.com"
			                },
			                "type": "email",
			                "key": "okta_email",
			                "id": "eael2v03sTTXEN7KW5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "deviceName": "OnePlus 5T"
			                },
			                "type": "app",
			                "key": "okta_verify",
			                "id": "pfdo31uccd05gLgmN5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "phoneNumber": "+1 XXX-XXX-3693"
			                },
			                "type": "phone",
			                "key": "phone_number",
			                "id": "paetnceczcDZduYCL5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "user": {
			        "type": "object",
			        "value": {
			            "id": "00ul0y27xJNbFnsRy5d6"
			        }
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
			    },
			    "app": {
			        "type": "object",
			        "value": {
			            "name": "oidc_client",
			            "label": "My Web App",
			            "id": "0oal6ssroFGvEU0Oe5d6"
			        }
			    }
			}`, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/challenge", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch challangeCall {
			case 0:
				challangeCall++
				s = fmt.Sprintf(`{
			    "version": "1.0.0",
			    "stateHandle": "b",
			    "expiresAt": "2021-05-31T17:42:10.000Z",
			    "intent": "LOGIN",
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
			                                "label": "Email",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hwe9EdtbCyKV5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "required": false,
			                                                "value": "email",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[0]"
			                            },
			                            {
			                                "label": "Okta Verify",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3e8k3bkOVrHAo5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "Enter a code",
			                                                        "value": "totp"
			                                                    },
			                                                    {
			                                                        "label": "Get a push notification",
			                                                        "value": "push"
			                                                    }
			                                                ]
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticators.value[1]"
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
			                                "relatesTo": "$.authenticatorEnrollments.value[2]"
			                            },
			                            {
			                                "label": "Phone",
			                                "value": {
			                                    "form": {
			                                        "value": [
			                                            {
			                                                "name": "id",
			                                                "required": true,
			                                                "value": "autl3hweaZ3zGU63b5d6",
			                                                "mutable": false
			                                            },
			                                            {
			                                                "name": "methodType",
			                                                "type": "string",
			                                                "required": false,
			                                                "options": [
			                                                    {
			                                                        "label": "SMS",
			                                                        "value": "sms"
			                                                    }
			                                                ]
			                                            },
			                                            {
			                                                "name": "enrollmentId",
			                                                "required": true,
			                                                "value": "paetnceczcDZduYCL5d6",
			                                                "mutable": false
			                                            }
			                                        ]
			                                    }
			                                },
			                                "relatesTo": "$.authenticatorEnrollments.value[3]"
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
			    "currentAuthenticatorEnrollment": {
			        "type": "object",
			        "value": {
			            "recover": {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "recover",
			                "href": "http://%s/idp/idx/recover",
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
			            },
			            "type": "password",
			            "key": "okta_password",
			            "id": "lae1bm7l17eiudHus5d6",
			            "displayName": "Password",
			            "methods": [
			                {
			                    "type": "password"
			                }
			            ]
			        }
			    },
			    "authenticators": {
			        "type": "array",
			        "value": [
			            {
			                "type": "email",
			                "key": "okta_email",
			                "id": "autl3hwe9EdtbCyKV5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "type": "app",
			                "key": "okta_verify",
			                "id": "autl3e8k3bkOVrHAo5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "type": "password",
			                "key": "okta_password",
			                "id": "autl3hwe8llr6CyxE5d6",
			                "displayName": "Password",
			                "methods": [
			                    {
			                        "type": "password"
			                    }
			                ]
			            },
			            {
			                "type": "phone",
			                "key": "phone_number",
			                "id": "autl3hweaZ3zGU63b5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "authenticatorEnrollments": {
			        "type": "array",
			        "value": [
			            {
			                "profile": {
			                    "email": "b***x@okta.com"
			                },
			                "type": "email",
			                "key": "okta_email",
			                "id": "eael2v03sTTXEN7KW5d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "deviceName": "OnePlus 5T"
			                },
			                "type": "app",
			                "key": "okta_verify",
			                "id": "pfdo31uccd05gLgmN5d6",
			                "displayName": "Okta Verify",
			                "methods": [
			                    {
			                        "type": "push"
			                    },
			                    {
			                        "type": "totp"
			                    }
			                ]
			            },
			            {
			                "type": "password",
			                "key": "okta_password",
			                "id": "lae1bm7l17eiudHus5d6",
			                "displayName": "Password",
			                "methods": [
			                    {
			                        "type": "password"
			                    }
			                ]
			            },
			            {
			                "profile": {
			                    "phoneNumber": "+1 XXX-XXX-3693"
			                },
			                "type": "phone",
			                "key": "phone_number",
			                "id": "paetnceczcDZduYCL5d6",
			                "displayName": "Phone",
			                "methods": [
			                    {
			                        "type": "sms"
			                    }
			                ]
			            }
			        ]
			    },
			    "user": {
			        "type": "object",
			        "value": {
			            "id": "00ul0y27xJNbFnsRy5d6"
			        }
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
			    },
			    "app": {
			        "type": "object",
			        "value": {
			            "name": "oidc_client",
			            "label": "My Web App",
			            "id": "0oal6ssroFGvEU0Oe5d6"
			        }
			    }
			}`, r.Host, r.Host, r.Host, r.Host)
			case 1:
				challangeCall++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "b",
				    "expiresAt": "2021-05-31T18:01:24.000Z",
				    "intent": "LOGIN",
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
				                                "label": "Email",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hwe9EdtbCyKV5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "email",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticatorEnrollments.value[0]"
				                            },
				                            {
				                                "label": "Okta Verify",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "Enter a code",
				                                                        "value": "totp"
				                                                    },
				                                                    {
				                                                        "label": "Get a push notification",
				                                                        "value": "push"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            },
				                            {
				                                "label": "Phone",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweaZ3zGU63b5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            },
				                                            {
				                                                "name": "enrollmentId",
				                                                "required": true,
				                                                "value": "paetnceczcDZduYCL5d6",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticatorEnrollments.value[2]"
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
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "profile": {
				                "deviceName": "OnePlus 5T"
				            },
				            "resend": {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "resend",
				                "href": "http://%s/idp/idx/challenge",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "authenticator",
				                        "required": true,
				                        "value": {
				                            "methodType": "push",
				                            "id": "autl3e8k3bkOVrHAo5d6"
				                        },
				                        "visible": false,
				                        "mutable": false
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
				            "type": "app",
				            "key": "okta_verify",
				            "id": "autl3e8k3bkOVrHAo5d6",
				            "displayName": "Okta Verify",
				            "methods": [
				                {
				                    "type": "push"
				                }
				            ]
				        }
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "autl3hwe9EdtbCyKV5d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "app",
				                "key": "okta_verify",
				                "id": "autl3e8k3bkOVrHAo5d6",
				                "displayName": "Okta Verify",
				                "methods": [
				                    {
				                        "type": "push"
				                    },
				                    {
				                        "type": "totp"
				                    }
				                ]
				            },
				            {
				                "type": "phone",
				                "key": "phone_number",
				                "id": "autl3hweaZ3zGU63b5d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "profile": {
				                    "email": "b***x@okta.com"
				                },
				                "type": "email",
				                "key": "okta_email",
				                "id": "eael2v03sTTXEN7KW5d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "profile": {
				                    "deviceName": "OnePlus 5T"
				                },
				                "type": "app",
				                "key": "okta_verify",
				                "id": "pfdo31uccd05gLgmN5d6",
				                "displayName": "Okta Verify",
				                "methods": [
				                    {
				                        "type": "push"
				                    },
				                    {
				                        "type": "totp"
				                    }
				                ]
				            },
				            {
				                "profile": {
				                    "phoneNumber": "+1 XXX-XXX-3693"
				                },
				                "type": "phone",
				                "key": "phone_number",
				                "id": "paetnceczcDZduYCL5d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00ul0y27xJNbFnsRy5d6"
				        }
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal6ssroFGvEU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
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
			        "href": "http://%s/oauth2/ggg/v1/token",
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
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/oauth2/ggg/v1/token", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
			    "token_type": "Bearer",
			    "expires_in": 3600,
			    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			    "scope": "openid profile",
			    "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
			}`))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		client, err := NewClientWithSettings(
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
			Credentials: Credentials{
				Password: "qwerty",
			},
		}
		resp, err = resp.Identify(context.TODO(), up)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepCancel)
		require.Contains(t, resp.AvailableSteps(), LoginStepOktaVerify)

		resp, err = resp.OktaVerify(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), LoginStepSuccess)
	})
	t.Run("identify_providers", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "name": "redirect-idp",
			                "type": "FACEBOOK",
			                "idp": {
			                    "id": "iogJ89dcUfMlckln",
			                    "name": "Facebook IdP"
			                },
			                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=aaaaaa&request_uri=urn:okta:pHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QT",
			                "method": "GET"
			            },
			            {
			                "name": "redirect-idp",
			                "type": "GOOGLE",
			                "idp": {
			                    "id": "ahp6ytrw2JOfKouz",
			                    "name": "Google IdP"
			                },
			                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=aaaaaa&request_uri=urn:okta:pHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QTpHaGkSwcrdpizfWIH0QT",
			                "method": "GET"
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
			}`))
		})

		ts := httptest.NewServer(mux)
		defer ts.Close()

		client, err := NewClientWithSettings(
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
		require.Contains(t, resp.AvailableSteps(), LoginStepProviderIdentify)
	})
}

func TestClient_Authenticate(t *testing.T) {
	t.Run("use of recovery_token", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()

			rts := r.Form["recovery_token"]
			rt := rts[0]
			assert.Equal(t, "abc123", rt)

			w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
				"version": "1.0.0",
				"stateHandle": "02ggggggggggggggggggggggggggggg-nFdddddddd",
				"expiresAt": "2022-01-27T20:19:13.000Z",
				"intent": "LOGIN",
				"remediation": {
					"type": "array",
					"value": [{
						"rel": ["create-form"],
						"name": "reset-authenticator",
						"relatesTo": ["$.currentAuthenticator"],
						"href": "https://%s/idp/idx/challenge/answer",
						"method": "POST",
						"produces": "application/ion+json; okta-version=1.0.0",
						"value": [{
							"name": "credentials",
							"type": "object",
							"form": {
								"value": [{
									"name": "passcode",
									"label": "New password",
									"secret": true
								}]
							},
							"required": true
						}, {
							"name": "stateHandle",
							"required": true,
							"value": "02ggggggggggggggggggggggggggggg-nFdddddddd",
							"visible": false,
							"mutable": false
						}],
						"accepts": "application/json; okta-version=1.0.0"
					}]
				},
				"currentAuthenticator": {
					"type": "object",
					"value": {
						"type": "password",
						"key": "okta_password",
						"id": "aut44444444444444444",
						"displayName": "Password",
						"methods": [{
							"type": "password"
						}],
						"settings": {
							"complexity": {
								"minLength": 8,
								"minLowerCase": 0,
								"minUpperCase": 0,
								"minNumber": 0,
								"minSymbol": 0,
								"excludeUsername": true,
								"excludeAttributes": []
							},
							"age": {
								"minAgeMinutes": 0,
								"historyCount": 4
							}
						}
					}
				},
				"authenticators": {
					"type": "array",
					"value": [{
						"type": "password",
						"key": "okta_password",
						"id": "aut44444444444444444",
						"displayName": "Password",
						"methods": [{
							"type": "password"
						}]
					}]
				},
				"authenticatorEnrollments": {
					"type": "array",
					"value": [{
						"type": "email",
						"key": "okta_email",
						"id": "eae44444444444444444",
						"displayName": "Email",
						"methods": [{
							"type": "email"
						}]
					}, {
						"type": "password",
						"key": "okta_password",
						"id": "lae33333333333333333",
						"displayName": "Password",
						"methods": [{
							"type": "password"
						}]
					}]
				},
				"recoveryAuthenticator": {
					"type": "object",
					"value": {
						"type": "password",
						"key": "okta_password",
						"id": "aut44444444444444444",
						"displayName": "Password",
						"methods": [{
							"type": "password"
						}],
						"settings": {
							"complexity": {
								"minLength": 8,
								"minLowerCase": 0,
								"minUpperCase": 0,
								"minNumber": 0,
								"minSymbol": 0,
								"excludeUsername": true,
								"excludeAttributes": []
							},
							"age": {
								"minAgeMinutes": 0,
								"historyCount": 4
							}
						}
					}
				},
				"user": {
					"type": "object",
					"value": {
						"id": "00u88888888888888888",
						"identifier": "some.one@example.com",
						"profile": {
							"firstName": "Some",
							"lastName": "One",
							"timeZone": "America/Los_Angeles",
							"locale": "en_US"
						}
					}
				},
				"cancel": {
					"rel": ["create-form"],
					"name": "cancel",
					"href": "https://%s/idp/idx/cancel",
					"method": "POST",
					"produces": "application/ion+json; okta-version=1.0.0",
					"value": [{
						"name": "stateHandle",
						"required": true,
						"value": "02ggggggggggggggggggggggggggggg-nFdddddddd",
						"visible": false,
						"mutable": false
					}],
					"accepts": "application/json; okta-version=1.0.0"
				},
				"app": {
					"type": "object",
					"value": {
						"name": "oidc_client",
						"label": "Cool Magic Link",
						"id": "0oa99999999999999999"
					}
				}
			}`, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
		})

		ts := httptest.NewServer(mux)
		defer ts.Close()

		client, err := NewClientWithSettings(
			WithClientID("foo"),
			WithClientSecret("bar"),
			WithIssuer(ts.URL),
			WithScopes([]string{"openid", "profile"}),
			WithRedirectURI(ts.URL+"/authorization-code/callback"))
		require.NoError(t, err)
		require.NotNil(t, client)
		client = client.WithHTTPClient(ts.Client())

		authOpts := AuthenticationOptions{
			RecoveryToken: "abc123",
		}
		ctx := context.TODO()
		resp, err := client.Authenticate(ctx, &authOpts)
		require.NoError(t, err)
		require.NotNil(t, resp)

		require.Contains(t, resp.AvailableSteps(), LoginStepCancel)
		require.Contains(t, resp.AvailableSteps(), LoginStepSetupNewPassword)
	})
}
