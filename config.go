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
	"errors"
	"fmt"
	"os"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/spf13/viper"
)

// config is a struct for configuration of the IDX client
type config struct {
	Okta struct {
		IDX struct {
			ClientID     string   `mapstructure:"clientId" schema:"client_id"`
			ClientSecret string   `mapstructure:"clientSecret" schema:"client_secret"`
			Issuer       string   `mapstructure:"issuer" schema:"-"`
			Scopes       []string `mapstructure:"scopes" schema:"scope"`
			RedirectURI  string   `mapstructure:"redirectUri" schema:"redirect_uri"`
		} `mapstructure:"idx"`
	} `mapstructure:"okta"`
}

// Validate validates the config
func (c config) Validate() error {
	return validation.ValidateStruct(&c.Okta.IDX,
		validation.Field(&c.Okta.IDX.ClientID, validation.Required),
		validation.Field(&c.Okta.IDX.ClientSecret, validation.Required),
		validation.Field(&c.Okta.IDX.Issuer, validation.Required),
		validation.Field(&c.Okta.IDX.Scopes, validation.Required),
		validation.Field(&c.Okta.IDX.RedirectURI, validation.Required),
	)
}

// ConfigSetter is a type allowing chaining configuration settings in code.
type ConfigSetter func(*config)

// WithClientID appends clientID on to the IDX config
func WithClientID(clientID string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientID = clientID
	}
}

// WithClientSecret appends clientSecret on to the IDX config
func WithClientSecret(clientSecret string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientSecret = clientSecret
	}
}

// WithIssuer appends issuer on to the IDX config
func WithIssuer(issuer string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Issuer = issuer
	}
}

// WithScopes appends scopes on to the IDX config
func WithScopes(scopes []string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Scopes = scopes
	}
}

// WithRedirectURI appends redirectURI on to the IDX config
func WithRedirectURI(redirectURI string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.RedirectURI = redirectURI
	}
}

// ReadEnvVars will check for environment variables for config settings
func (c *config) ReadEnvVars() {
	if os.Getenv("OKTA_IDX_ISSUER") != "" {
		c.Okta.IDX.Issuer = os.Getenv("OKTA_IDX_ISSUER")
	}
	if os.Getenv("OKTA_IDX_CLIENTID") != "" {
		c.Okta.IDX.ClientID = os.Getenv("OKTA_IDX_CLIENTID")
	}
	if os.Getenv("OKTA_IDX_CLIENTSECRET") != "" {
		c.Okta.IDX.ClientSecret = os.Getenv("OKTA_IDX_CLIENTSECRET")
	}
	if os.Getenv("OKTA_IDX_SCOPES") != "" {
		c.Okta.IDX.Scopes = strings.Split(os.Getenv("OKTA_IDX_SCOPES"), ",")
	}
	if os.Getenv("OKTA_IDX_REDIRECTURI") != "" {
		c.Okta.IDX.RedirectURI = os.Getenv("OKTA_IDX_REDIRECTURI")
	}
}

// ReadConfig reads config from file. Config file should be placed either in
// project root dir or in $HOME/.okta/ .
func ReadConfig(config interface{}, opts ...viper.DecoderConfigOption) error {
	v := viper.New()
	v.SetConfigName("okta")
	v.AddConfigPath("$HOME/.okta/")
	v.AddConfigPath(".")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("okta_idx")
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)
	err := v.ReadInConfig()
	if err != nil {
		var vErr viper.ConfigFileNotFoundError
		if !errors.As(err, &vErr) { // skip reading from file if it's not present
			return fmt.Errorf("failed to read from config file: %w", err)
		}
	}
	err = v.Unmarshal(config, opts...)
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	return nil
}
