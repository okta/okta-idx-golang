// +build unit

package idx

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		file, err := os.Create("okta.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file.Name())
		s := `okta:
  idx:
    client_id: "foo"
    client_secret: "bar"
    issuer: "https://okta.com"
    scopes: "openid,profile"
    code_challenge: "1"
    code_challenge_method: "S256"
    redirect_uri: "https://okta.com"
    state: "2"
`
		_, err = file.Write([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient()
		assert.NoError(t, err)
		assert.Equal(t, "foo", c.config.Okta.IDX.ClientID)
		assert.Equal(t, "bar", c.config.Okta.IDX.ClientSecret)
		assert.Equal(t, "https://okta.com", c.config.Okta.IDX.Issuer)
		assert.Equal(t, []string{"openid", "profile"}, c.config.Okta.IDX.Scopes)
		assert.Equal(t, "1", c.config.Okta.IDX.CodeChallenge)
		assert.Equal(t, "S256", c.config.Okta.IDX.CodeChallengeMethod)
		assert.Equal(t, "https://okta.com", c.config.Okta.IDX.RedirectURI)
		assert.Equal(t, "2", c.config.Okta.IDX.State)
	})
	t.Run("happy_path_rewrite", func(t *testing.T) {
		file, err := os.Create("okta.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file.Name())
		s := `okta:
  idx:
    client_id: "foo"
    client_secret: "bar"
    issuer: "https://okta.com"
    scopes: "openid,profile"
    code_challenge: "1"
    code_challenge_method: "S256"
    redirect_uri: "https://okta.com"
    state: "2"
`
		_, err = file.Write([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(WithClientSecret("changed"))
		assert.NoError(t, err)
		assert.Equal(t, "foo", c.config.Okta.IDX.ClientID)
		assert.Equal(t, "changed", c.config.Okta.IDX.ClientSecret)
		assert.Equal(t, "https://okta.com", c.config.Okta.IDX.Issuer)
		assert.Equal(t, []string{"openid", "profile"}, c.config.Okta.IDX.Scopes)
		assert.Equal(t, "1", c.config.Okta.IDX.CodeChallenge)
		assert.Equal(t, "S256", c.config.Okta.IDX.CodeChallengeMethod)
		assert.Equal(t, "https://okta.com", c.config.Okta.IDX.RedirectURI)
		assert.Equal(t, "2", c.config.Okta.IDX.State)
	})
	t.Run("invalid_configuration_file", func(t *testing.T) {
		file, err := os.Create("okta.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file.Name())
		s := `%%%%%`
		_, err = file.Write([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(WithClientSecret("changed"))
		assert.EqualError(t, err, "failed to create new Client: failed to read from config file: While parsing config: yaml: could not find expected directive name")
		assert.Nil(t, c)
	})
	t.Run("invalid_configuration", func(t *testing.T) {
		c, err := NewClient()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid configuration")
		assert.Nil(t, c)
	})
	t.Run("invalid_configuration_missing_client_id", func(t *testing.T) {
		c, err := NewClient(
			WithClientSecret("foo"),
			WithIssuer("bar"),
			WithScopes([]string{"openId"}),
			WithCodeChallenge("12345"),
			WithCodeChallengeMethod("S256"),
			WithRedirectURI("https://okta.com"),
			WithState("qwerty"),
		)
		assert.EqualError(t, err, "invalid configuration: ClientID: cannot be blank.")
		assert.Nil(t, c)
	})
}

func TestClient_Interact(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			assert.NoError(t, err)
			assert.Equal(t, "foo", r.PostForm.Get("client_id"))
			assert.Equal(t, "bar", r.PostForm.Get("client_secret"))
			assert.Equal(t, "1", r.PostForm.Get("code_challenge"))
			assert.Equal(t, "S256", r.PostForm.Get("code_challenge_method"))
			assert.Equal(t, "2", r.PostForm.Get("state"))
			assert.Equal(t, []string{"openid", "profile"}, r.PostForm["scope"])
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
		assert.Contains(t, err.Error(), `the API returned an error: 'stateHandle' is required.`)
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
		resp, err := client.Introspect(context.TODO(), &InteractionHandle{InteractionHandle: "abcd"})
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
		_, err := client.Introspect(context.TODO(), &InteractionHandle{InteractionHandle: "abcd"})
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
		_, err := client.Introspect(context.TODO(), &InteractionHandle{InteractionHandle: "abcd"})
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
		_, err := client.Introspect(context.TODO(), &InteractionHandle{InteractionHandle: "abcd"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `the API returned an error: The session has expired.`)
	})
}

func testConfig(url string) *config {
	return &config{
		Okta: struct {
			IDX struct {
				ClientID            string   `mapstructure:"client_id" schema:"client_id"`
				ClientSecret        string   `mapstructure:"client_secret" schema:"client_secret"`
				Issuer              string   `mapstructure:"issuer" schema:"-"`
				Scopes              []string `mapstructure:"scopes" schema:"scope"`
				CodeChallenge       string   `mapstructure:"code_challenge" schema:"code_challenge"`
				CodeChallengeMethod string   `mapstructure:"code_challenge_method" schema:"code_challenge_method"`
				RedirectURI         string   `mapstructure:"redirect_uri" schema:"redirect_uri"`
				State               string   `mapstrucutre:"state" schema:"state"`
			} `mapstructure:"idx"`
		}{
			IDX: struct {
				ClientID            string   `mapstructure:"client_id" schema:"client_id"`
				ClientSecret        string   `mapstructure:"client_secret" schema:"client_secret"`
				Issuer              string   `mapstructure:"issuer" schema:"-"`
				Scopes              []string `mapstructure:"scopes" schema:"scope"`
				CodeChallenge       string   `mapstructure:"code_challenge" schema:"code_challenge"`
				CodeChallengeMethod string   `mapstructure:"code_challenge_method" schema:"code_challenge_method"`
				RedirectURI         string   `mapstructure:"redirect_uri" schema:"redirect_uri"`
				State               string   `mapstrucutre:"state" schema:"state"`
			}{
				ClientID:            "foo",
				ClientSecret:        "bar",
				Issuer:              url,
				Scopes:              []string{"openid", "profile"},
				CodeChallenge:       "1",
				CodeChallengeMethod: "S256",
				RedirectURI:         url,
				State:               "2",
			},
		},
	}
}
