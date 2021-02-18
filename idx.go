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
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/okta/okta-idx-golang/oktahttp"
)

/**
 * Current version of the package. This is used mainly for our User-Agent
 */
const packageVersion = "0.1.0-beta.2"

var idx *Client

type Client struct {
	config     *config
	httpClient *http.Client
}

type Context struct {
	codeVerifier      string
	interactionHandle *InteractionHandle
	state             string
}

func NewClient(conf ...ConfigSetter) (*Client, error) {
	oie := &Client{}
	cfg := &config{}
	err := ReadConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Client: %w", err)
	}
	for _, confSetter := range conf {
		confSetter(cfg)
	}
	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	oie.config = cfg
	oie.httpClient = &http.Client{Timeout: time.Second * 60}

	idx = oie
	return oie, nil
}

func (c *Client) WithHTTPClient(client *http.Client) *Client {
	c.httpClient = client
	return c
}

func (c *Client) GetClientSecret() string {
	return c.config.Okta.IDX.ClientSecret
}

func (ictx *Context) GetCodeVerifier() string {
	return ictx.codeVerifier
}

func (ictx *Context) GetInteractionHandle() *InteractionHandle {
	return ictx.interactionHandle
}

func (ictx *Context) GetState() string {
	return ictx.state
}

func unmarshalResponse(r *http.Response, i interface{}) error {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		var respErr ErrorResponse
		err = json.Unmarshal(body, &respErr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body: %w", err)
		}
		return &respErr
	}
	err = json.Unmarshal(body, &i)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	return nil
}

func (c *Client) createCodeVerifier() (*string, error) {
	codeVerifier := make([]byte, 86)
	_, err := crand.Read(codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("error creating code_verifier: %w", err)
	}

	s := base64.RawURLEncoding.EncodeToString(codeVerifier)
	return &s, nil
}

func (c *Client) createState() (*string, error) {
	localState := make([]byte, 16)
	_, err := crand.Read(localState)
	if err != nil {
		return nil, fmt.Errorf("error creating state: %w", err)
	}
	s := base64.RawURLEncoding.EncodeToString(localState)
	return &s, nil
}

func (c *Client) Interact(ctx context.Context, state *string) (*Context, error) {
	h := sha256.New()
	var err error

	idxContext := &Context{}

	codeVerifier, err := c.createCodeVerifier()
	if err != nil {
		return nil, err
	}
	idxContext.codeVerifier = *codeVerifier

	if state == nil {
		state, err = c.createState()
		if err != nil {
			return nil, err
		}
	}
	idxContext.state = *state

	_, err = h.Write([]byte(idxContext.GetCodeVerifier()))
	if err != nil {
		return nil, fmt.Errorf("failed to write codeVerifier: %w", err)
	}

	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	data := url.Values{}
	data.Set("client_id", c.config.Okta.IDX.ClientID)
	data.Set("scope", strings.Join(c.config.Okta.IDX.Scopes, " "))
	data.Set("code_challenge", codeChallenge)
	data.Set("code_challenge_method", "S256")
	data.Set("redirect_uri", c.config.Okta.IDX.RedirectURI)
	data.Set("state", idxContext.GetState())

	endpoint := c.config.Okta.IDX.Issuer + "/v1/interact"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create interact http request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := c.httpClient.Do(req)
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

	idxContext.interactionHandle = &InteractionHandle{
		InteractionHandle: interactionHandle.InteractionHandle,
	}

	return idxContext, nil
}

func (c *Client) Introspect(ctx context.Context, idxContext *Context) (*Response, error) {
	domain, err := url.Parse(c.config.Okta.IDX.Issuer)
	if err != nil {
		return nil, fmt.Errorf("could not parse issuer: %w", err)
	}

	ictx := idxContext

	if ictx == nil {
		idxContext, err = c.Interact(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve an interaction handle for you: %w", err)
		}

		ictx = idxContext
	}

	body, err := json.Marshal(ictx.GetInteractionHandle())
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
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := c.httpClient.Do(req)
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
