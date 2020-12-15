/**
 * Copyright 2017 - Present Okta, Inc.
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
const packageVersion = "0.0.1-alpha.1"

var idx *Client

type Client struct {
	config       *config
	httpClient   *http.Client
	codeVerifier string
	state        string
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

	codeVerifier := make([]byte, 86)
	_, err = crand.Read(codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("error creating code_verifier: %w", err)
	}

	oie.codeVerifier = base64.RawURLEncoding.EncodeToString(codeVerifier[:])

	state := make([]byte, 16)
	_, err = crand.Read(state)
	if err != nil {
		return nil, fmt.Errorf("error creating state: %w", err)
	}

	oie.state = base64.RawURLEncoding.EncodeToString(state[:])

	idx = oie
	return oie, nil
}

func (c *Client) WithHTTPClient(client *http.Client) *Client {
	c.httpClient = client
	return c
}

func (c *Client) GetCodeVerifier() string {
	return c.codeVerifier
}

func (c *Client) GetState() string {
	return c.state
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

func (c *Client) Interact(ctx context.Context) (*InteractionHandle, error) {
	h := sha256.New()
	h.Write([]byte(c.GetCodeVerifier()))

	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	data := url.Values{}
	data.Set("client_id", c.config.Okta.IDX.ClientID)
	data.Set("scope", strings.Join(c.config.Okta.IDX.Scopes, " "))
	data.Set("code_challenge", codeChallenge)
	data.Set("code_challenge_method", "S256")
	data.Set("redirect_uri", c.config.Okta.IDX.RedirectURI)
	data.Set("state", c.GetState())

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
	return &InteractionHandle{
		InteractionHandle: interactionHandle.InteractionHandle,
	}, nil
}

func (c *Client) Introspect(ctx context.Context, interactionHandle *InteractionHandle) (*Response, error) {
	domain, err := url.Parse(c.config.Okta.IDX.Issuer)
	if err != nil {
		return nil, fmt.Errorf("could not parse issuer: %w", err)
	}
	body, err := json.Marshal(interactionHandle)
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
