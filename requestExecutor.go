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
	"net/http"
	"time"

	"github.com/okta/okta-idx-golang/oktaHttp"
)

type RequestMarshaler interface {
	Marshal() ([]byte, error)
	NewRequest(ctx context.Context, oie *IDXClient) (*http.Request, error)
}

type RequestExecutor struct {
	httpClient *http.Client

	accept      string
	contentType string
}

func NewRequestExecutor(httpClient *http.Client) *RequestExecutor {
	re := &RequestExecutor{}
	re.httpClient = httpClient

	if httpClient == nil {
		transport := &http.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
		re.httpClient = &http.Client{
			Transport: transport,
		}
	}

	return re
}

func (re *RequestExecutor) WithAccept(acceptHeader string) *RequestExecutor {
	re.accept = acceptHeader
	return re
}

func (re *RequestExecutor) GetHttpClient() *http.Client {
	return re.httpClient
}

func (re *RequestExecutor) NewRequest(method string, url string, body RequestMarshaler) (*http.Request, error) {
	contentBytes, err := body.Marshal()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(contentBytes))
	if err != nil {
		return nil, err
	}

	oktaHttp.WithOktaUserAgent(req, packageVersion)

	req.Header.Add("Accept", re.accept)

	return req, nil
}
