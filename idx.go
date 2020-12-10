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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/okta/okta-idx-golang/oktahttp"
)

/**
 * Current version of the package. This is used mainly for our User-Agent
 */
const packageVersion = "0.0.1-alpha.1"

var idx *Client

type Client struct {
	config     *config
	httpClient *http.Client
}

func NewClient(conf ...ConfigSetter) (*Client, error) {
	oie := &Client{}
	cfg := &config{}
	err := ReadConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Client: %v", err)
	}
	for _, confSetter := range conf {
		confSetter(cfg)
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

func unmarshalResponse(r *http.Response, i interface{}) error {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	if r.StatusCode != http.StatusOK {
		var respErr ErrorResponse
		err = json.Unmarshal(body, &respErr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body: %v", err)
		}
		return &respErr
	}
	err = json.Unmarshal(body, &i)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %v", err)
	}
	return nil
}

func (c *Client) Interact(ctx context.Context) (*InteractionHandle, error) {
	data := url.Values{}
	err := schema.NewEncoder().Encode(&c.config.Okta.IDX, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode interaction request: %v", err)
	}
	endpoint := c.config.Okta.IDX.Issuer + "/v1/interact"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create interact http request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %v", err)
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
		return nil, fmt.Errorf("could not parse issuer: %v", err)
	}
	body, err := json.Marshal(interactionHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interaction handle: %v", err)
	}
	endpoint := domain.Scheme + "://" + domain.Host + "/idp/idx/introspect"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/ion+json; okta-version=1.0.0")
	req.Header.Add("Accept", "application/ion+json; okta-version=1.0.0")
	oktahttp.WithOktaUserAgent(req, packageVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %v", err)
	}
	var idxResponse Response
	err = unmarshalResponse(resp, &idxResponse)
	if err != nil {
		return nil, err
	}
	return &idxResponse, nil
}
