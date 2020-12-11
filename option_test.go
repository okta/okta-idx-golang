// +build unit

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
)

var (
	remediation = `{
    "remediation": {
        "type": "array",
        "value": [
            {
                "href": "%s/idp/idx/identify",
                "method": "POST",
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
                        "value": "efg",
                        "visible": false,
                        "mutable": false
                    }
                ],
                "accepts": "application/ion+json; okta-version=1.0.0"
            }
        ]
    }
}`
	validInput = `{
    "credentials": {
        "passcode": "qwerty"
    }
}`
)

func TestRemediationOption_Proceed(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			ih := make(map[string]interface{})
			err = json.Unmarshal(body, &ih)
			assert.NoError(t, err)
			assert.Equal(t, "qwerty", ih["credentials"].(map[string]interface{})["passcode"])
			assert.Equal(t, "efg", ih["stateHandle"])
			b := `{
    "successWithInteractionCode": {
        "rel": [
            "create-form"
        ],
        "name": "issue",
        "href": "https://example.com/oauth2/v1/token",
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
                "value": "code"
            },
            {
                "name": "client_id",
                "required": true,
                "value": "abcd"
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
}`
			w.Write([]byte(b))
		}))
		defer ts.Close()
		idx = &Client{
			httpClient: ts.Client(),
		}
		rem := fmt.Sprintf(remediation, ts.URL)
		var resp Response
		err := json.Unmarshal([]byte(rem), &resp)
		assert.NoError(t, err)
		assert.False(t, resp.LoginSuccess())
		data := []byte(validInput)
		respNext, err := resp.Remediation.RemediationOptions[0].Proceed(context.TODO(), data)
		assert.NoError(t, err)
		assert.True(t, respNext.LoginSuccess())
	})
	t.Run("missing_required_field", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer ts.Close()
		idx = &Client{
			httpClient: ts.Client(),
		}
		rem := fmt.Sprintf(remediation, ts.URL)
		var resp Response
		err := json.Unmarshal([]byte(rem), &resp)
		assert.NoError(t, err)
		assert.False(t, resp.LoginSuccess())
		data := []byte(`{
    "foo": "bar"
}`)
		respNext, err := resp.Remediation.RemediationOptions[0].Proceed(context.TODO(), data)
		assert.EqualError(t, err, `missing 'credentials' property from input`)
		assert.Nil(t, respNext)
	})
	t.Run("http_client_error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()
		idx = &Client{
			httpClient: ts.Client(),
		}
		rem := fmt.Sprintf(remediation, ts.URL)
		var resp Response
		err := json.Unmarshal([]byte(rem), &resp)
		assert.NoError(t, err)
		assert.False(t, resp.LoginSuccess())
		data := []byte(validInput)
		respNext, err := resp.Remediation.RemediationOptions[0].Proceed(context.TODO(), data)
		assert.Nil(t, respNext)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "http call has failed")
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
                "message": "Password is incorrect",
                "i18n": {
                    "key": "incorrectPassword"
                },
                "class": "ERROR"
            }
        ]
    }
}`))
		}))
		defer ts.Close()
		idx = &Client{
			httpClient: ts.Client(),
		}
		rem := fmt.Sprintf(remediation, ts.URL)
		var resp Response
		err := json.Unmarshal([]byte(rem), &resp)
		assert.NoError(t, err)
		assert.False(t, resp.LoginSuccess())
		data := []byte(validInput)
		respNext, err := resp.Remediation.RemediationOptions[0].Proceed(context.TODO(), data)
		assert.Nil(t, respNext)
		assert.Error(t, err)
		assert.EqualError(t, err, "the API returned an error: Password is incorrect")
	})
}
