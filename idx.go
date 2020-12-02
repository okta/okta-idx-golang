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
	"os"
	"strings"

	"github.com/pkg/errors"
)

/**
 * Current version of the package. This is used mainly for our User-Agent
 */
const packageVersion = "0.0.1-alpha.1"

var IDXC IDXClient

type IDXClient struct {
	config          *config
	requestExecutor *RequestExecutor
}

type IDX interface {
	Start(ctx context.Context, interactionHandle *string) (IDXResponse, error)
}

func NewIDXClient(conf ...ConfigSetter) (*IDXClient, error) {
	oie := &IDXClient{}
	cfg := &config{}

	err := ReadConfig(cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "Error with config")
	}

	for _, confSetter := range conf {
		confSetter(cfg)
	}

	oie.config = cfg

	httpClient := &http.Client{}
	oie.requestExecutor = NewRequestExecutor(httpClient)

	IDXC = *oie

	return oie, nil
}

func (oie *IDXClient) Start(ctx context.Context, interactionHandle *InteractionHandle) (*IDXResponse, error) {
	if interactionHandle == nil {

		interactRequest := &InteractRequest{
			ClientId:     oie.config.Okta.IDX.ClientId,
			ClientSecret: oie.config.Okta.IDX.ClientSecret,
			Scope:        strings.Join(oie.config.Okta.IDX.Scopes, " "),
		}

		req, err := interactRequest.NewRequest(ctx, oie)
		if err != nil {
			return nil, err
		}

		resp, err := oie.requestExecutor.GetHttpClient().Do(req)
		if err != nil {
			return nil, err
		}

		body, _ := ioutil.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &interactionHandle)

	}

	// We should have an interaction handle at this point. If it is nil, lets return an error
	if interactionHandle == nil {
		return nil, errors.New("we need an interaction handle in order to proceed. We were not able to find on.")
	}

	introspectRequest := &IntrospectRequest{
		InteractionHandle: interactionHandle.InteractionHandle,
	}

	req, err := introspectRequest.NewRequest(ctx, oie)

	resp, err := oie.requestExecutor.GetHttpClient().Do(req)
	if err != nil {
		return nil, err
	}

	idxr := &IDXResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, idxr)
	if err != nil {
		return nil, err
	}

	return idxr, nil
}

func printcURL(req *http.Request) error {
	var (
		command string
		b       []byte
		err     error
	)
	if req.URL != nil {
		command = fmt.Sprintf("curl -X %s '%s'", req.Method, req.URL.String())
	}
	for k, v := range req.Header {
		command += fmt.Sprintf(" -H '%s: %s'", k, strings.Join(v, ", "))
	}
	if req.Body != nil {
		b, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		command += fmt.Sprintf(" -d %q", string(b))
	}
	fmt.Fprintf(os.Stderr, "cURL Command: %s\n", command)
	// reset body
	body := bytes.NewBuffer(b)
	req.Body = ioutil.NopCloser(body)
	return nil
}
