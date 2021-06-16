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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_InitProfileEnroll(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		var callIntrospect, callAnswer, callCredentialsEnroll int
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch callIntrospect {
			case 0:
				callIntrospect++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T13:03:29.000Z",
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
				                        "value": "a",
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
				                        "value": "a",
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
				                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=0oal7aaroFDvEU0Fe5d8&request_uri=urn:okta:RRD",
				                "method": "GET"
				            },
				            {
				                "name": "redirect-idp",
				                "type": "GOOGLE",
				                "idp": {
				                    "id": "0oasgv6yj2ZQrW9fF5d6",
				                    "name": "Google IdP"
				                },
				                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=0oal7aaroFDvEU0Fe5d8&request_uri=urn:okta:AAD",
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 1:
				callIntrospect++
				s = fmt.Sprintf(`{
    				"version": "1.0.0",
    				"stateHandle": "a",
    				"expiresAt": "2021-05-24T11:08:31.000Z",
    				"intent": "LOGIN",
    				"remediation": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "select-authenticator-enroll",
    				            "href": "http://%s/idp/idx/credential/enroll",
    				            "method": "POST",
    				            "produces": "application/ion+json; okta-version=1.0.0",
    				            "value": [
    				                {
    				                    "name": "authenticator",
    				                    "type": "object",
    				                    "options": [
    				                        {
    				                            "label": "Password",
    				                            "value": {
    				                                "form": {
    				                                    "value": [
    				                                        {
    				                                            "name": "id",
    				                                            "required": true,
    				                                            "value": "autl5hwe8llr6DyxA5d6",
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
    				                            "relatesTo": "$.authenticators.value[0]"
    				                        }
    				                    ]
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
    				"authenticators": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "type": "password",
    				            "key": "okta_password",
    				            "id": "autl5hwe8llr6DyxA5d6",
    				            "displayName": "Password",
    				            "methods": [
    				                {
    				                    "type": "password"
    				                }
    				            ]
    				        }
    				    ]
    				},
    				"authenticatorEnrollments": {
    				    "type": "array",
    				    "value": []
    				},
    				"user": {
    				    "type": "object",
    				    "value": {
    				        "id": "00usvypodlPeAXfxj5d6"
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
    				            "value": "a",
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
    				        "id": "0oal7aaroFDvEU0Fe5d8"
    				    }
    				}
			}`, r.Host, r.Host)
			case 2:
				callIntrospect++
				s = fmt.Sprintf(`{
    				"version": "1.0.0",
    				"stateHandle": "a",
    				"expiresAt": "2021-05-24T11:08:33.000Z",
    				"intent": "LOGIN",
    				"remediation": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "select-authenticator-enroll",
    				            "href": "http://%s/idp/idx/credential/enroll",
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
    				                            "relatesTo": "$.authenticators.value[0]"
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
    				                                            "name": "channel",
    				                                            "type": "string",
    				                                            "required": false,
    				                                            "options": [
    				                                                {
    				                                                    "label": "QRCODE",
    				                                                    "value": "qrcode"
    				                                                },
    				                                                {
    				                                                    "label": "EMAIL",
    				                                                    "value": "email"
    				                                                },
    				                                                {
    				                                                    "label": "SMS",
    				                                                    "value": "sms"
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
    				                                            "name": "phoneNumber",
    				                                            "label": "Phone number",
    				                                            "required": false
    				                                        }
    				                                    ]
    				                                }
    				                            },
    				                            "relatesTo": "$.authenticators.value[2]"
    				                        }
    				                    ]
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
    				            "type": "password",
    				            "key": "okta_password",
    				            "id": "lae1tw8lqvmrZib1i5d6",
    				            "displayName": "Password",
    				            "methods": [
    				                {
    				                    "type": "password"
    				                }
    				            ]
    				        }
    				    ]
    				},
    				"user": {
    				    "type": "object",
    				    "value": {
    				        "id": "00usvypodlPeAXfxj5d6"
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
    				            "value": "a",
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
    				        "id": "0oal7aaroFDvEU0Fe5d8"
    				    }
    				}
				}`, r.Host, r.Host)
			case 3:
				callIntrospect++
				s = fmt.Sprintf(`{
    				"version": "1.0.0",
    				"stateHandle": "a",
    				"expiresAt": "2021-05-24T11:08:34.000Z",
    				"intent": "LOGIN",
    				"remediation": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "enroll-authenticator",
    				            "relatesTo": [
    				                "$.currentAuthenticator"
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
    				                                "label": "Enter code"
    				                            }
    				                        ]
    				                    },
    				                    "required": true
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
    				        },
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "select-authenticator-enroll",
    				            "href": "http://%s/idp/idx/credential/enroll",
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
    				                            "relatesTo": "$.authenticators.value[0]"
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
    				                                            "name": "channel",
    				                                            "type": "string",
    				                                            "required": false,
    				                                            "options": [
    				                                                {
    				                                                    "label": "QRCODE",
    				                                                    "value": "qrcode"
    				                                                },
    				                                                {
    				                                                    "label": "EMAIL",
    				                                                    "value": "email"
    				                                                },
    				                                                {
    				                                                    "label": "SMS",
    				                                                    "value": "sms"
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
    				                                            "name": "phoneNumber",
    				                                            "label": "Phone number",
    				                                            "required": false
    				                                        }
    				                                    ]
    				                                }
    				                            },
    				                            "relatesTo": "$.authenticators.value[2]"
    				                        }
    				                    ]
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
    				"currentAuthenticator": {
    				    "type": "object",
    				    "value": {
    				        "resend": {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "resend",
    				            "href": "http://%s/idp/idx/challenge/resend",
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
    				        },
    				        "poll": {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "poll",
    				            "href": "http://%s/idp/idx/challenge/poll",
    				            "method": "POST",
    				            "produces": "application/ion+json; okta-version=1.0.0",
    				            "refresh": 4000,
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
    				        },
    				        "type": "email",
    				        "key": "okta_email",
    				        "id": "autl3hwe9EdtbCyKV5d6",
    				        "displayName": "Email",
    				        "methods": [
    				            {
    				                "type": "email"
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
    				            "type": "password",
    				            "key": "okta_password",
    				            "id": "lae1tw8lqvmrZib1i5d6",
    				            "displayName": "Password",
    				            "methods": [
    				                {
    				                    "type": "password"
    				                }
    				            ]
    				        }
    				    ]
    				},
    				"enrollmentAuthenticator": {
    				    "type": "object",
    				    "value": {
    				        "type": "email",
    				        "key": "okta_email",
    				        "id": "autl3hwe9EdtbCyKV5d6",
    				        "displayName": "Email",
    				        "methods": [
    				            {
    				                "type": "email"
    				            }
    				        ]
    				    }
    				},
    				"user": {
    				    "type": "object",
    				    "value": {
    				        "id": "00usvypodlPeAXfxj5d6"
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
    				            "value": "a",
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
    				        "id": "0oal7aaroFDvEU0Fe5d8"
    				    }
    				}
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 4:
				callIntrospect++
				s = fmt.Sprintf(`{
    				"version": "1.0.0",
    				"stateHandle": "a",
    				"expiresAt": "2021-05-24T11:09:04.000Z",
    				"intent": "LOGIN",
    				"remediation": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "select-authenticator-enroll",
    				            "href": "http://%s/idp/idx/credential/enroll",
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
    				                                            "value": "autl3e8k3bkOVrHAo5d6",
    				                                            "mutable": false
    				                                        },
    				                                        {
    				                                            "name": "channel",
    				                                            "type": "string",
    				                                            "required": false,
    				                                            "options": [
    				                                                {
    				                                                    "label": "QRCODE",
    				                                                    "value": "qrcode"
    				                                                },
    				                                                {
    				                                                    "label": "EMAIL",
    				                                                    "value": "email"
    				                                                },
    				                                                {
    				                                                    "label": "SMS",
    				                                                    "value": "sms"
    				                                                }
    				                                            ]
    				                                        }
    				                                    ]
    				                                }
    				                            },
    				                            "relatesTo": "$.authenticators.value[0]"
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
    				                                            "name": "phoneNumber",
    				                                            "label": "Phone number",
    				                                            "required": false
    				                                        }
    				                                    ]
    				                                }
    				                            },
    				                            "relatesTo": "$.authenticators.value[1]"
    				                        },
    				                        {
    				                            "label": "Security Question",
    				                            "value": {
    				                                "form": {
    				                                    "value": [
    				                                        {
    				                                            "name": "id",
    				                                            "required": true,
    				                                            "value": "autl3hweb4k9heUlG5d6",
    				                                            "mutable": false
    				                                        },
    				                                        {
    				                                            "name": "methodType",
    				                                            "required": false,
    				                                            "value": "security_question",
    				                                            "mutable": false
    				                                        }
    				                                    ]
    				                                }
    				                            },
    				                            "relatesTo": "$.authenticators.value[2]"
    				                        }
    				                    ]
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
    				        },
    				        {
    				            "rel": [
    				                "create-form"
    				            ],
    				            "name": "skip",
    				            "href": "http://%s/idp/idx/skip",
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
    				    ]
    				},
    				"authenticators": {
    				    "type": "array",
    				    "value": [
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
    				        },
    				        {
    				            "type": "security_question",
    				            "key": "security_question",
    				            "id": "autl3hweb4k9heUlG5d6",
    				            "displayName": "Security Question",
    				            "methods": [
    				                {
    				                    "type": "security_question"
    				                }
    				            ]
    				        }
    				    ]
    				},
    				"authenticatorEnrollments": {
    				    "type": "array",
    				    "value": [
    				        {
    				            "type": "email",
    				            "key": "okta_email",
    				            "id": "eaesvypp7G7HGW3f45d6",
    				            "displayName": "Email",
    				            "methods": [
    				                {
    				                    "type": "email"
    				                }
    				            ]
    				        },
    				        {
    				            "type": "password",
    				            "key": "okta_password",
    				            "id": "lae1tw8lqvmrZib1i5d6",
    				            "displayName": "Password",
    				            "methods": [
    				                {
    				                    "type": "password"
    				                }
    				            ]
    				        }
    				    ]
    				},
    				"user": {
    				    "type": "object",
    				    "value": {
    				        "id": "00usvypodlPeAXfxj5d6"
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
    				            "value": "a",
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
    				        "id": "0oal7aaroFDvEU0Fe5d8"
    				    }
    				}
				}`, r.Host, r.Host, r.Host)
			case 5:
				callIntrospect++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:05.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
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
				                                    "label": "Enter code"
				                                }
				                            ]
				                        },
				                        "required": true
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
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
				                                                "name": "phoneNumber",
				                                                "label": "Phone number",
				                                                "required": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[2]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "resend": {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "resend",
				                "href": "http://%s/idp/idx/challenge/resend",
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
				            },
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
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				            },
				            {
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
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
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 6:
				callIntrospect++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:31.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
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
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			case 7:
				callIntrospect++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:32.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
				                ],
				                "href": "http://%s/idp/idx/challenge/answer",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "credentials",
				                        "type": "object",
				                        "required": true,
				                        "options": [
				                            {
				                                "label": "Choose a security question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "questionKey",
				                                                "type": "string",
				                                                "label": "Choose a security question",
				                                                "required": true,
				                                                "options": [
				                                                    {
				                                                        "label": "What is the food you least liked as a child?",
				                                                        "value": "disliked_food"
				                                                    }
				                                                ]
				                                            },
				                                            {
				                                                "name": "answer",
				                                                "label": "Answer",
				                                                "required": true
				                                            }
				                                        ]
				                                    }
				                                }
				                            },
				                            {
				                                "label": "Create my own security question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "questionKey",
				                                                "required": true,
				                                                "value": "custom",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "question",
				                                                "label": "Create a security question",
				                                                "required": true
				                                            },
				                                            {
				                                                "name": "answer",
				                                                "label": "Answer",
				                                                "required": true
				                                            }
				                                        ]
				                                    }
				                                }
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "contextualData": {
				                "questionKeys": [
				                    "custom",
				                    "disliked_food"
				                ],
				                "questions": [
				                    {
				                        "questionKey": "disliked_food",
				                        "question": "What is the food you least liked as a child?"
				                    }
				                ]
				            },
				            "type": "security_question",
				            "key": "security_question",
				            "id": "autl3hweb4k9heUlG5d6",
				            "displayName": "Security Question",
				            "methods": [
				                {
				                    "type": "security_question"
				                }
				            ]
				        }
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "security_question",
				            "key": "security_question",
				            "id": "autl3hweb4k9heUlG5d6",
				            "displayName": "Security Question",
				            "methods": [
				                {
				                    "type": "security_question"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host)
			case 8:
				callIntrospect++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:34.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
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
				                        "value": "a",
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
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            },
				            {
				                "type": "security_question",
				                "key": "security_question",
				                "id": "qaesvrwmt1pYlnGSK5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/enroll", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T13:03:30.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-profile",
				                "href": "http://%s/idp/idx/enroll/new",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "userProfile",
				                        "form": {
				                            "value": [
				                                {
				                                    "name": "firstName",
				                                    "label": "First name",
				                                    "required": true,
				                                    "minLength": 1,
				                                    "maxLength": 50
				                                },
				                                {
				                                    "name": "lastName",
				                                    "label": "Last name",
				                                    "required": true,
				                                    "minLength": 1,
				                                    "maxLength": 50
				                                },
				                                {
				                                    "name": "email",
				                                    "label": "Email",
				                                    "required": true
				                                }
				                            ]
				                        }
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-identify",
				                "href": "http://%s/idp/idx/identify/select",
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
				    },
				    "app": {
				        "type": "object",
				        "value": {
				            "name": "oidc_client",
				            "label": "My Web App",
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/enroll/new", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:08:31.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "authenticator",
				                        "type": "object",
				                        "options": [
				                            {
				                                "label": "Password",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl5hwe8llr6DyxA5d6",
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
				                                "relatesTo": "$.authenticators.value[0]"
				                            }
				                        ]
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
				    "authenticators": {
				        "type": "array",
				        "value": [
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "autl5hwe8llr6DyxA5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": []
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/credential/enroll", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch callCredentialsEnroll {
			case 0:
				callCredentialsEnroll++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:08:32.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
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
				                                    "label": "Enter password",
				                                    "secret": true
				                                }
				                            ]
				                        },
				                        "required": true
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "authenticator",
				                        "type": "object",
				                        "options": [
				                            {
				                                "label": "Password",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl5hwe8llr6DyxA5d6",
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
				                                "relatesTo": "$.authenticators.value[0]"
				                            }
				                        ]
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
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl5hwe8llr6DyxA5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ],
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
				        "value": [
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "autl5hwe8llr6DyxA5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": []
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl5hwe8llr6DyxA5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ],
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
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			case 1:
				callCredentialsEnroll++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:08:34.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
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
				                                    "label": "Enter code"
				                                }
				                            ]
				                        },
				                        "required": true
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                "relatesTo": "$.authenticators.value[0]"
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
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
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
				                                                "name": "phoneNumber",
				                                                "label": "Phone number",
				                                                "required": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[2]"
				                            }
				                        ]
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
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "resend": {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "resend",
				                "href": "http://%s/idp/idx/challenge/resend",
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
				            },
				            "poll": {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "poll",
				                "href": "http://%s/idp/idx/challenge/poll",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "refresh": 4000,
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
				            },
				            "type": "email",
				            "key": "okta_email",
				            "id": "autl3hwe9EdtbCyKV5d6",
				            "displayName": "Email",
				            "methods": [
				                {
				                    "type": "email"
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
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "email",
				            "key": "okta_email",
				            "id": "autl3hwe9EdtbCyKV5d6",
				            "displayName": "Email",
				            "methods": [
				                {
				                    "type": "email"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 2:
				callCredentialsEnroll++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:05.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
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
				                                    "label": "Enter code"
				                                }
				                            ]
				                        },
				                        "required": true
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
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
				                                                "name": "phoneNumber",
				                                                "label": "Phone number",
				                                                "required": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[2]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "resend": {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "resend",
				                "href": "http://%s/idp/idx/challenge/resend",
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
				            },
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
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				            },
				            {
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
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
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 3:
				callCredentialsEnroll++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:32.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "enroll-authenticator",
				                "relatesTo": [
				                    "$.currentAuthenticator"
				                ],
				                "href": "http://%s/idp/idx/challenge/answer",
				                "method": "POST",
				                "produces": "application/ion+json; okta-version=1.0.0",
				                "value": [
				                    {
				                        "name": "credentials",
				                        "type": "object",
				                        "required": true,
				                        "options": [
				                            {
				                                "label": "Choose a security question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "questionKey",
				                                                "type": "string",
				                                                "label": "Choose a security question",
				                                                "required": true,
				                                                "options": [
				                                                    {
				                                                        "label": "What is the food you least liked as a child?",
				                                                        "value": "disliked_food"
				                                                    }
				                                                ]
				                                            },
				                                            {
				                                                "name": "answer",
				                                                "label": "Answer",
				                                                "required": true
				                                            }
				                                        ]
				                                    }
				                                }
				                            },
				                            {
				                                "label": "Create my own security question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "questionKey",
				                                                "required": true,
				                                                "value": "custom",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "question",
				                                                "label": "Create a security question",
				                                                "required": true
				                                            },
				                                            {
				                                                "name": "answer",
				                                                "label": "Answer",
				                                                "required": true
				                                            }
				                                        ]
				                                    }
				                                }
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "contextualData": {
				                "questionKeys": [
				                    "custom",
				                    "disliked_food"
				                ],
				                "questions": [
				                    {
				                        "questionKey": "disliked_food",
				                        "question": "What is the food you least liked as a child?"
				                    }
				                ]
				            },
				            "type": "security_question",
				            "key": "security_question",
				            "id": "autl3hweb4k9heUlG5d6",
				            "displayName": "Security Question",
				            "methods": [
				                {
				                    "type": "security_question"
				                }
				            ]
				        }
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            }
				        ]
				    },
				    "enrollmentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "security_question",
				            "key": "security_question",
				            "id": "autl3hweb4k9heUlG5d6",
				            "displayName": "Security Question",
				            "methods": [
				                {
				                    "type": "security_question"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/challenge/answer", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch callAnswer {
			case 0:
				callAnswer++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:08:33.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                "relatesTo": "$.authenticators.value[0]"
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
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
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
				                                                "name": "phoneNumber",
				                                                "label": "Phone number",
				                                                "required": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[2]"
				                            }
				                        ]
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
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host)
			case 1:
				callAnswer++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:04.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
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
				                                                "name": "phoneNumber",
				                                                "label": "Phone number",
				                                                "required": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[2]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				            },
				            {
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			case 2:
				callAnswer++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:31.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
				                                                    }
				                                                ]
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[0]"
				                            },
				                            {
				                                "label": "Security Question",
				                                "value": {
				                                    "form": {
				                                        "value": [
				                                            {
				                                                "name": "id",
				                                                "required": true,
				                                                "value": "autl3hweb4k9heUlG5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "methodType",
				                                                "required": false,
				                                                "value": "security_question",
				                                                "mutable": false
				                                            }
				                                        ]
				                                    }
				                                },
				                                "relatesTo": "$.authenticators.value[1]"
				                            }
				                        ]
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
				            },
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				                "type": "security_question",
				                "key": "security_question",
				                "id": "autl3hweb4k9heUlG5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
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
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			case 3:
				callAnswer++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:09:34.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "select-authenticator-enroll",
				                "href": "http://%s/idp/idx/credential/enroll",
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
				                                                "value": "autl3e8k3bkOVrHAo5d6",
				                                                "mutable": false
				                                            },
				                                            {
				                                                "name": "channel",
				                                                "type": "string",
				                                                "required": false,
				                                                "options": [
				                                                    {
				                                                        "label": "QRCODE",
				                                                        "value": "qrcode"
				                                                    },
				                                                    {
				                                                        "label": "EMAIL",
				                                                        "value": "email"
				                                                    },
				                                                    {
				                                                        "label": "SMS",
				                                                        "value": "sms"
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
				                        "value": "a",
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
				                "name": "skip",
				                "href": "http://%s/idp/idx/skip",
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
				        ]
				    },
				    "authenticators": {
				        "type": "array",
				        "value": [
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
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvypp7G7HGW3f45d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            },
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tw8lqvmrZib1i5d6",
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
				                "id": "paesvvqme2R8WniF75d6",
				                "displayName": "Phone",
				                "methods": [
				                    {
				                        "type": "sms"
				                    }
				                ]
				            },
				            {
				                "type": "security_question",
				                "key": "security_question",
				                "id": "qaesvrwmt1pYlnGSK5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/skip", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T11:05:35.000Z",
				    "intent": "LOGIN",
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvypodlPeAXfxj5d6"
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
				                "value": "a",
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
				            "id": "0oal7aaroFDvEU0Fe5d8"
				        }
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
				                "value": "md855nqRQjX-TPaXR3KiNQ2XxWwhC_shvLtbKBtaDFY"
				            },
				            {
				                "name": "client_id",
				                "required": true,
				                "value": "0oal7aaroFDvEU0Fe5d8"
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

		client, err := NewClient(
			WithClientID("foo"),
			WithClientSecret("bar"),
			WithIssuer(ts.URL),
			WithScopes([]string{"openid", "profile"}),
			WithRedirectURI(ts.URL+"/authorization-code/callback"))
		require.NoError(t, err)
		require.NotNil(t, client)
		client = client.WithHTTPClient(ts.Client())

		up := &UserProfile{
			LastName:  "John",
			FirstName: "Doe",
			Email:     "john.doe@okta.com",
		}
		resp, err := client.InitProfileEnroll(context.TODO(), up)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPasswordSetup)

		resp, err = resp.SetNewPassword(context.TODO(), "Sfdf22fdwMN!00!")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepEmailVerification)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPhoneVerification)

		resp, err = resp.VerifyEmail(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepEmailVerification)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepEmailConfirmation)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPhoneVerification)

		resp, err = resp.ConfirmEmail(context.TODO(), "123456")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPhoneVerification)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSecurityQuestionOptions)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSkip)

		resp, err = resp.VerifyPhone(context.TODO(), PhoneMethodSMS, "+12345713693")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPhoneVerification)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepPhoneConfirmation)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSecurityQuestionOptions)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSkip)

		resp, err = resp.ConfirmPhone(context.TODO(), "123456")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSecurityQuestionOptions)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSkip)

		var q map[string]string
		resp, q, err = resp.SecurityQuestionOptions(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, q, 2)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSecurityQuestionOptions)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSecurityQuestionSetup)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSkip)

		resp, err = resp.SetupSecurityQuestion(context.TODO(), &SecurityQuestion{
			QuestionKey: "disliked_food",
			Answer:      "Natto",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepCancel)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSkip)

		resp, err = resp.Skip(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), EnrollmentStepSuccess)
		require.NotNil(t, resp.Token())
	})
}
