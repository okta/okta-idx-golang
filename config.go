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
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	viperDefaultDelimiter = "."
	defaultTagName        = "default"
	squashTagValue        = ",squash"
	mapStructureTagName   = "mapstructure"
)

type config struct {
	Okta struct {
		Client struct {
			OIE struct {
				ClientId     string   `mapstructure:"clientId"`
				ClientSecret string   `mapstructure:"clientSecret"`
				Issuer       string   `mapstructure:"issuer"`
				Scopes       []string `mapstructure:"scopes"`
			} `mapstructure:"oie"`
		} `mapstructure:"client"`
	} `mapstructure:"okta"`
}

type ConfigSetter func(*config)

func WithClientId(clientId string) ConfigSetter {
	return func(c *config) {
		c.Okta.Client.OIE.ClientId = clientId
	}
}

func WithClientSecret(clientSecret string) ConfigSetter {
	return func(c *config) {
		c.Okta.Client.OIE.ClientSecret = clientSecret
	}
}

func WithIssuer(issuer string) ConfigSetter {
	return func(c *config) {
		c.Okta.Client.OIE.Issuer = issuer
	}
}

func WithScopes(scopes []string) ConfigSetter {
	return func(c *config) {
		c.Okta.Client.OIE.Scopes = scopes
	}
}

func ReadConfig(config interface{}, opts ...viper.DecoderConfigOption) error {
	v := viper.New()
	v.SetConfigName("okta")
	v.AddConfigPath("$HOME/.okta/")                                      // path to look for the config file in
	v.AddConfigPath(".")                                                 // path to look for config in the working directory
	v.SetEnvKeyReplacer(strings.NewReplacer(viperDefaultDelimiter, "_")) // replace default viper delimiter for env vars
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	err := v.ReadInConfig() // read from configuration file
	if err != nil {
		return errors.WithMessage(err, "failed to read from config file")
	}
	err = v.Unmarshal(config, opts...) // unmarshal into config struct
	if err != nil {
		return errors.WithMessage(err, "failed to parse configuration")
	}

	return nil
}
