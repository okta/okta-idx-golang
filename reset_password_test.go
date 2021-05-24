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

func TestClient_InitPasswordReset(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		var call, callAnswer, callRecover int
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/interact", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"interaction_handle":"a"}`))
		})
		mux.HandleFunc("/idp/idx/introspect", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch call {
			case 0:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T12:19:13.000Z",
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
				                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=0oal6aaroFGvFU0Oe5d6&request_uri=urn:okta:RS15emVWX2h3VkpWZUNUNXQtc2VWVEg1MmdHaGRpbS12a2ZBd3VXaldPQTowb2FzZ2xxeGdnUnJDTVFBVzVkNg",
				                "method": "GET"
				            },
				            {
				                "name": "redirect-idp",
				                "type": "GOOGLE",
				                "idp": {
				                    "id": "0oasgv6yj2ZQrW9fF5d6",
				                    "name": "Google IdP"
				                },
				                "href": "http://%s/oauth2/ggg/v1/authorize?client_id=0oal6aaroFGvFU0Oe5d6&request_uri=urn:okta:RS15emVWX2h3VkpWZUNUNXQtc2VWVEg1MmdHaGRpbS12a2ZBd3VXaldPQTowb2FzZ3Y2eWoyWlFyVzlmRjVkNg",
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host, r.Host)
			case 1:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:24:15.000Z",
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
				                        "value": "a",
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
				                        "value": "a",
				                        "visible": false,
				                        "mutable": false
				                    }
				                ],
				                "accepts": "application/json; okta-version=1.0.0"
				            },
				            "type": "password",
				            "key": "okta_password",
				            "id": "lae1tv1idgdk00rJI5d6",
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
				                "type": "password",
				                "key": "okta_password",
				                "id": "autl3hwe8llr6CyxE5d6",
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
				        "value": [
				            {
				                "type": "password",
				                "key": "okta_password",
				                "id": "lae1tv1idgdk00rJI5d6",
				                "displayName": "Password",
				                "methods": [
				                    {
				                        "type": "password"
				                    }
				                ]
				            }
				        ]
				    },
				    "recoveryAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvcxjymtMJzN6m5d6"
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host)
			case 2:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:24:17.000Z",
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
				            }
				        ]
				    },
				    "currentAuthenticatorEnrollment": {
				        "type": "object",
				        "value": {
				            "profile": {
				                "email": "b***1@gmail.com"
				            },
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
				            "id": "eaesvafroFdWYoeM25d6",
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
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "profile": {
				                    "email": "b***1@gmail.com"
				                },
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvafroFdWYoeM25d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            }
				        ]
				    },
				    "recoveryAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvcxjymtMJzN6m5d6"
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host, r.Host, r.Host)
			case 3:
				call++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:24:26.000Z",
				    "intent": "LOGIN",
				    "remediation": {
				        "type": "array",
				        "value": [
				            {
				                "rel": [
				                    "create-form"
				                ],
				                "name": "reset-authenticator",
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
				                                    "label": "New password",
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
				            }
				        ]
				    },
				    "currentAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
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
				                "id": "autl3hwe8llr6CyxE5d6",
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
				        "value": [
				            {
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvafroFdWYoeM25d6",
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
				                "id": "lae1tv1idgdk00rJI5d6",
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
				                "id": "paesvc9q9z8Wv7px35d6",
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
				                "id": "qaesveavdB9isngPL5d6",
				                "displayName": "Security Question",
				                "methods": [
				                    {
				                        "type": "security_question"
				                    }
				                ]
				            }
				        ]
				    },
				    "recoveryAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
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
				            "id": "00usvcxjymtMJzN6m5d6"
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/identify", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "version": "1.0.0",
			    "stateHandle": "a",
			    "expiresAt": "2021-05-24T10:00:55.000Z",
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
			                        "value": "a",
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
			                        "value": "a",
			                        "visible": false,
			                        "mutable": false
			                    }
			                ],
			                "accepts": "application/json; okta-version=1.0.0"
			            },
			            "type": "password",
			            "key": "okta_password",
			            "id": "lae1tv1idgdk00rJI5d6",
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
			                "type": "password",
			                "key": "okta_password",
			                "id": "autl3hwe8llr6CyxE5d6",
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
			        "value": [
			            {
			                "type": "password",
			                "key": "okta_password",
			                "id": "lae1tv1idgdk00rJI5d6",
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
			            "id": "00usvcxjymtMJzN6m5d6"
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
			    }
			}`, r.Host, r.Host, r.Host)
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/recover", func(w http.ResponseWriter, r *http.Request) {
			var s string
			switch callRecover {
			case 0:
				callRecover++
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:24:15.000Z",
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
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "profile": {
				                    "email": "b***1@gmail.com"
				                },
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvafroFdWYoeM25d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            }
				        ]
				    },
				    "recoveryAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvcxjymtMJzN6m5d6"
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host)
			case 1:
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:24:16.000Z",
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
				            }
				        ]
				    },
				    "authenticatorEnrollments": {
				        "type": "array",
				        "value": [
				            {
				                "profile": {
				                    "email": "b***1@gmail.com"
				                },
				                "type": "email",
				                "key": "okta_email",
				                "id": "eaesvafroFdWYoeM25d6",
				                "displayName": "Email",
				                "methods": [
				                    {
				                        "type": "email"
				                    }
				                ]
				            }
				        ]
				    },
				    "recoveryAuthenticator": {
				        "type": "object",
				        "value": {
				            "type": "password",
				            "key": "okta_password",
				            "id": "autl3hwe8llr6CyxE5d6",
				            "displayName": "Password",
				            "methods": [
				                {
				                    "type": "password"
				                }
				            ]
				        }
				    },
				    "user": {
				        "type": "object",
				        "value": {
				            "id": "00usvcxjymtMJzN6m5d6"
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
				            "id": "0oal6aaroFGvFU0Oe5d6"
				        }
				    }
				}`, r.Host, r.Host)
			}
			_, _ = w.Write([]byte(s))
		})
		mux.HandleFunc("/idp/idx/challenge", func(w http.ResponseWriter, r *http.Request) {
			s := fmt.Sprintf(`{
			    "version": "1.0.0",
			    "stateHandle": "a",
			    "expiresAt": "2021-05-24T10:00:57.000Z",
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
			            }
			        ]
			    },
			    "currentAuthenticatorEnrollment": {
			        "type": "object",
			        "value": {
			            "profile": {
			                "email": "b***1@gmail.com"
			            },
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
			            "id": "eaesvafroFdWYoeM25d6",
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
			            }
			        ]
			    },
			    "authenticatorEnrollments": {
			        "type": "array",
			        "value": [
			            {
			                "profile": {
			                    "email": "b***1@gmail.com"
			                },
			                "type": "email",
			                "key": "okta_email",
			                "id": "eaesvafroFdWYoeM25d6",
			                "displayName": "Email",
			                "methods": [
			                    {
			                        "type": "email"
			                    }
			                ]
			            }
			        ]
			    },
			    "recoveryAuthenticator": {
			        "type": "object",
			        "value": {
			            "type": "password",
			            "key": "okta_password",
			            "id": "autl3hwe8llr6CyxE5d6",
			            "displayName": "Password",
			            "methods": [
			                {
			                    "type": "password"
			                }
			            ]
			        }
			    },
			    "user": {
			        "type": "object",
			        "value": {
			            "id": "00usvcxjymtMJzN6m5d6"
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
			    }
			}`, r.Host, r.Host, r.Host, r.Host)
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
			    "expiresAt": "2021-05-24T10:01:21.000Z",
			    "intent": "LOGIN",
			    "remediation": {
			        "type": "array",
			        "value": [
			            {
			                "rel": [
			                    "create-form"
			                ],
			                "name": "reset-authenticator",
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
			                                    "label": "New password",
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
			            }
			        ]
			    },
			    "currentAuthenticator": {
			        "type": "object",
			        "value": {
			            "type": "password",
			            "key": "okta_password",
			            "id": "autl3hwe8llr6CyxE5d6",
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
			                "id": "autl3hwe8llr6CyxE5d6",
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
			        "value": [
			            {
			                "type": "email",
			                "key": "okta_email",
			                "id": "eaesvafroFdWYoeM25d6",
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
			                "id": "lae1tv1idgdk00rJI5d6",
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
			                "id": "paesvc9q9z8Wv7px35d6",
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
			                "id": "qaesveavdB9isngPL5d6",
			                "displayName": "Security Question",
			                "methods": [
			                    {
			                        "type": "security_question"
			                    }
			                ]
			            }
			        ]
			    },
			    "recoveryAuthenticator": {
			        "type": "object",
			        "value": {
			            "type": "password",
			            "key": "okta_password",
			            "id": "autl3hwe8llr6CyxE5d6",
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
			            "id": "00usvcxjymtMJzN6m5d6"
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
			    }
			}`, r.Host, r.Host)
			case 1:
				s = fmt.Sprintf(`{
				    "version": "1.0.0",
				    "stateHandle": "a",
				    "expiresAt": "2021-05-24T10:20:28.000Z",
				    "intent": "LOGIN",
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
				                "value": "value"
				            },
				            {
				                "name": "client_id",
				                "required": true,
				                "value": "0oal6aaroFGvFU0Oe5d6"
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
			}
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

		ir := &IdentifyRequest{
			Identifier: "test.user@okta.com",
		}
		resp, err := client.InitPasswordReset(context.TODO(), ir)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepCancel)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepEmailVerification)

		resp, err = resp.VerifyEmail(context.TODO())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepCancel)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepEmailConfirmation)

		resp, err = resp.ConfirmEmail(context.TODO(), "123456")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepCancel)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepNewPassword)

		resp, err = resp.SetNewPassword(context.TODO(), "BHdfKdf!edf22Fsx")
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.AvailableSteps(), ResetPasswordStepSuccess)
		require.NotNil(t, resp.Token())
	})
}
