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
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

const (
	packageVersion      = "0.2.1"
	defaultPollInterval = time.Second * 3
	defaultTimeout      = time.Second * 60
	CodeVerifierSize    = 86
	StateSize           = 16
)

var idx *Client

type AccessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	DeviceSecret string `json:"device_secret"`
}

// Client is the IDX client.
type Client struct {
	config     *Config
	httpClient *http.Client
	debug      bool
}

type Context struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
	InteractionHandle   *InteractionHandle
	State               string
}

type InteractionHandle struct {
	InteractionHandle string `json:"interactionHandle"`
}

type interactOptions struct {
	activationToken string
	recoveryToken   string
}

// NewClient New client constructor that is configured with configuration file
// and environment variables.
func NewClient() (*Client, error) {
	return NewClientWithSettings(func(c *Config) {})
}

// NewClientWithSettings New client constructor that is configured with
// configuration file, environment variables, and then any overriding setters.
func NewClientWithSettings(conf ...ConfigSetter) (*Client, error) {
	cfg := &Config{}

	// read configuration from config file first
	err := ReadConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Client: %w", err)
	}

	// override configuration settings with those set by env vars
	cfg.ReadEnvVars()

	// override configuration settings with setters
	for _, confSetter := range conf {
		confSetter(cfg)
	}
	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	c := &Client{
		config:     cfg,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	if os.Getenv("DEBUG_IDX_CLIENT") != "" {
		c.debug = true
	}

	idx = c
	return c, nil
}

// WithHTTPClient Convenience method to chain settings on the client.
func (c *Client) WithHTTPClient(client *http.Client) *Client {
	c.httpClient = client
	return c
}

// ClientSecret The IDX Client's Secret.
func (c *Client) ClientSecret() string {
	return c.config.Okta.IDX.ClientSecret
}

// Config the client's configuration
func (c *Client) Config() *Config {
	return c.config
}

func (c *Client) introspect(ctx context.Context, ih *InteractionHandle) (*Response, error) {
	domain, err := url.Parse(c.config.Okta.IDX.Issuer)
	if err != nil {
		return nil, fmt.Errorf("could not parse issuer: %w", err)
	}
	body, err := json.Marshal(ih)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interaction handle: %w", err)
	}
	endpoint := domain.Scheme + "://" + domain.Host + "/idp/idx/introspect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspect http request: %w", err)
	}
	req.Header.Add("Content-Type", "application/ion+json; okta-version=1.0.0")
	req.Header.Add("Accept", "application/ion+json; okta-version=1.0.0")
	withOktaUserAgent(req)
	resp, err := c.httpClientDo(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %w", err)
	}
	var idxResponse Response
	err = unmarshalResponse(resp, &idxResponse)
	if err != nil {
		return nil, err
	}
	return &idxResponse, nil
}

// interact Gets the current interact response context.
func (c *Client) interact(ctx context.Context, opts *interactOptions) (*Context, error) {
	h := sha256.New()
	var err error

	idxContext := &Context{}
	idxContext.CodeVerifier, err = createCodeVerifier()
	if err != nil {
		return nil, err
	}

	idxContext.State, err = createState()
	if err != nil {
		return nil, err
	}

	_, err = h.Write([]byte(idxContext.CodeVerifier))
	if err != nil {
		return nil, fmt.Errorf("failed to write codeVerifier: %w", err)
	}

	idxContext.CodeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	idxContext.CodeChallengeMethod = "S256"

	data := c.interactValues(idxContext, opts)
	endpoint := c.oAuthEndPoint("interact")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create interact http request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	withDeviceContext(ctx, req)

	resp, err := c.httpClientDo(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %w", err)
	}
	type interactionHandleResponse struct {
		InteractionHandle string `json:"interaction_handle"`
	}
	var interactionHandle interactionHandleResponse
	err = unmarshalResponse(resp, &interactionHandle)
	if err != nil {
		return nil, err
	}
	idxContext.InteractionHandle = &InteractionHandle{
		InteractionHandle: interactionHandle.InteractionHandle,
	}
	return idxContext, nil
}

func (c *Client) interactValues(ctx *Context, opts *interactOptions) *url.Values {
	data := url.Values{}
	data.Set("client_id", c.config.Okta.IDX.ClientID)
	data.Set("scope", strings.Join(c.config.Okta.IDX.Scopes, " "))
	data.Set("code_challenge", ctx.CodeChallenge)
	data.Set("code_challenge_method", ctx.CodeChallengeMethod)
	data.Set("redirect_uri", c.config.Okta.IDX.RedirectURI)
	data.Set("state", ctx.State)
	if opts != nil {
		if opts.activationToken != "" {
			data.Set("activation_token", opts.activationToken)
		}
		if opts.recoveryToken != "" {
			data.Set("recovery_token", opts.recoveryToken)
		}
	}

	return &data
}

// RedeemInteractionCode Calls the token api with given interactionCode and returns an AccessToken
func (c *Client) RedeemInteractionCode(ctx context.Context, idxContext *Context, interactionCode string) (*AccessToken, error) {
	params := url.Values{
		"grant_type":       {"interaction_code"},
		"interaction_code": {interactionCode},
		"client_id":        {c.config.Okta.IDX.ClientID},
		"client_secret":    {c.config.Okta.IDX.ClientSecret},
		"code_verifier":    {idxContext.CodeVerifier},
	}
	tokenEndpoint := c.oAuthEndPoint(fmt.Sprintf("token?%s", params.Encode()))

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, http.NoBody)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	withOktaUserAgent(req)

	resp, err := c.httpClientDo(req)
	if err != nil {
		return nil, fmt.Errorf("error calling token api: %w", err)
	}

	var accessToken AccessToken
	err = unmarshalResponse(resp, &accessToken)
	if err != nil {
		return nil, fmt.Errorf("error with token api response: %w", err)
	}

	_, err = c.verifyToken(accessToken.IDToken)
	if err != nil {
		return nil, fmt.Errorf("error with token api response: %w", err)
	}

	return &accessToken, nil
}

func (c *Client) verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["aud"] = c.config.Okta.IDX.ClientID
	jv := verifier.JwtVerifier{
		Issuer:           c.config.Okta.IDX.Issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%w; token: %s", err, t)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified, result nil")
}

func (c *Client) RevokeToken(ctx context.Context, accessToken string) error {
	data := url.Values{
		"token_type_hint": {"access_token"},
		"token":           {accessToken},
	}
	revokeEndpoint := c.oAuthEndPoint("revoke")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, revokeEndpoint, strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	withOktaUserAgent(req)

	_, err := c.httpClient.Do(req)
	return err
}

func (c *Client) oAuthEndPoint(operation string) string {
	var endPoint string
	issuer := c.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		endPoint = fmt.Sprintf("%s/v1/%s", issuer, operation)
	} else {
		endPoint = fmt.Sprintf("%s/oauth2/v1/%s", issuer, operation)
	}
	return endPoint
}

func withOktaUserAgent(req *http.Request) {
	userAgent := fmt.Sprintf("okta-idx-golang/%s golang/%s %s/%s", packageVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	req.Header.Add("User-Agent", userAgent)
}

func withDeviceContext(ctx context.Context, req *http.Request) {
	withOktaUserAgent(req)

	for i := range deviceContextKeys {
		v := ctx.Value(deviceContextKeys[i])
		if val, ok := v.(string); ok {
			req.Header.Set(string(deviceContextKeys[i]), val)
		}
	}
}

func unmarshalResponse(r *http.Response, i interface{}) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if r.StatusCode == http.StatusOK {
		err = json.Unmarshal(body, &i)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body: %w", err)
		}
		return nil
	}
	var errIDX ResponseError
	err = json.Unmarshal(body, &errIDX)
	if err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			errIDX.ErrorDescription = string(body)
			errIDX.ErrorType = strconv.Itoa(r.StatusCode)
			return &errIDX
		}
		return fmt.Errorf("failed to unmarshal error response body: %w", err)
	}
	if errIDX.Message.Type == "" && errIDX.ErrorSummary == "" {
		err = digUpMessage(body, &errIDX, i)
		if err != nil {
			return err
		}
	}
	return &errIDX
}

func digUpMessage(body []byte, respErr *ResponseError, i interface{}) error {
	resp, ok := i.(*Response)
	if !ok {
		return nil
	}
	err := json.Unmarshal(body, &i)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	for j := range resp.Remediation.RemediationOptions {
		for k := range resp.Remediation.RemediationOptions[j].FormValues {
			if resp.Remediation.RemediationOptions[j].FormValues[k].Form != nil {
				for l := range resp.Remediation.RemediationOptions[j].FormValues[k].Form.FormValues {
					if resp.Remediation.RemediationOptions[j].FormValues[k].Form.FormValues[l].Message != nil {
						respErr.Message.Type = resp.Remediation.RemediationOptions[j].FormValues[k].Form.FormValues[l].Message.Type
						respErr.Message.Values = resp.Remediation.RemediationOptions[j].FormValues[k].Form.FormValues[l].Message.Values
					}
				}
			}
		}
	}
	return nil
}

func createCodeVerifier() (string, error) {
	codeVerifier := make([]byte, CodeVerifierSize)
	_, err := crand.Read(codeVerifier)
	if err != nil {
		return "", fmt.Errorf("error creating code_verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(codeVerifier), nil
}

func createState() (string, error) {
	localState := make([]byte, StateSize)
	if _, err := crand.Read(localState); err != nil {
		return "", fmt.Errorf("error creating state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(localState), nil
}

func passcodeAuth(ctx context.Context, idxContext *Context, remediation, passcode string) (*Response, error) {
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption(remediation)
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(passcode)))
	return ro.proceed(ctx, credentials)
}

func webAuthNCredentials(ctx context.Context, idxContext *Context, remediation string, credentials *WebAuthNVerifyCredentials) (*Response, error) {
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption(remediation)
	if err != nil {
		return nil, err
	}
	data := []byte(fmt.Sprintf(`{
				"credentials": {
					"attestation": "%s",
					"clientData": "%s"
				}
			}`, credentials.Attestation, credentials.ClientData))
	return ro.proceed(ctx, data)
}

func verifyEmail(ctx context.Context, idxContext *Context, authenticatorOption string) (*Response, error) {
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption(authenticatorOption, "Email", true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	return ro.proceed(ctx, authenticator)
}

func setPassword(ctx context.Context, idxContext *Context, optionName, password string) (*Response, error) {
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption(optionName)
	if err != nil {
		return nil, err
	}
	credentials := []byte(`{
		"credentials": {
			"passcode": "` + strings.TrimSpace(password) + `"
		}
	}`)
	return ro.proceed(ctx, credentials)
}

func enrollAuthenticator(ctx context.Context, handle *InteractionHandle, authenticatorLabel string) (*Response, error) {
	resp, err := idx.introspect(ctx, handle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", authenticatorLabel, true)
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	return ro.proceed(ctx, authenticator)
}

const customQuestion = "custom"

func securityQuestionSetup(ctx context.Context, idxContext *Context, sq *SecurityQuestion) (*Response, error) {
	if sq.QuestionKey == "" {
		return nil, errors.New("missing security question key")
	}
	if sq.Answer == "" {
		return nil, errors.New("missing answer for the security question key")
	}
	if sq.QuestionKey == customQuestion && sq.Question == "" {
		return nil, errors.New("missing custom question")
	}
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	if sq.QuestionKey == customQuestion {
		clearOptionsForCustomKey(ro)
	}
	credentials, _ := json.Marshal(&struct {
		Credentials *SecurityQuestion `json:"credentials"`
	}{Credentials: sq})
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func securityQuestionOptions(ctx context.Context, idxContext *Context) (*Response, SecurityQuestions, error) {
	resp, err := idx.introspect(ctx, idxContext.InteractionHandle)
	if err != nil {
		return nil, nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Security Question", true)
	if err != nil {
		return nil, nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string)
	ro, err = resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, nil, err
	}
	v, err := ro.value("credentials")
	if err != nil {
		return nil, nil, err
	}
	for i := range v.Options {
		if v.Options[i].Label == "Choose a security question" {
			obj := v.Options[i].Value.(FormOptionsValueObject).Form.Value
			for j := range obj {
				if obj[j].Name == "questionKey" {
					for k := range obj[j].Options {
						m[string(obj[j].Options[k].Value.(FormOptionsValueString))] = obj[j].Options[k].Label
					}
				}
			}
		}
	}
	m["custom"] = "Create a security question"
	return resp, m, nil
}

func (c *Client) debugRequest(req *http.Request) {
	if req == nil {
		return
	}
	reqData, err := httputil.DumpRequest(req, true)
	if err == nil {
		log.Printf("[DEBUG] "+logReqMsg, req.RequestURI, prettyPrintJsonLines(reqData))
	} else {
		log.Printf("[ERROR] %s API Request error: %#v", req.RequestURI, err)
	}
}

func (c *Client) debugResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	respData, err := httputil.DumpResponse(resp, true)
	if err == nil {
		log.Printf("[DEBUG] "+logRespMsg, resp.Request.RequestURI, prettyPrintJsonLines(respData))
	} else {
		log.Printf("[ERROR] %s API Response error: %#v", resp.Request.RequestURI, err)
	}
}

func (c *Client) httpClientDo(req *http.Request) (*http.Response, error) {
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.httpClient.Do(req)
	if c.debug {
		c.debugResponse(resp)
	}

	return resp, err
}

// prettyPrintJsonLines iterates through a []byte line-by-line, transforming any
// lines that are complete json into pretty-printed json.
func prettyPrintJsonLines(b []byte) string {
	parts := strings.Split(string(b), "\n")
	for i, p := range parts {
		if b := []byte(p); json.Valid(b) {
			var out bytes.Buffer
			json.Indent(&out, b, "", " ")
			parts[i] = out.String()
		}
	}
	return strings.Join(parts, "\n")
}

const logReqMsg = `%s API Request Details:
---[ REQUEST ]---------------------------------------
%s
-----------------------------------------------------`

const logRespMsg = `%s API Response Details:
---[ RESPONSE ]--------------------------------------
%s
-----------------------------------------------------`
