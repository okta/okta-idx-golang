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
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type config struct {
	Okta struct {
		IDX struct {
			ClientID            string   `mapstructure:"client_id" schema:"client_id"`
			ClientSecret        string   `mapstructure:"client_secret" schema:"client_secret"`
			Issuer              string   `mapstructure:"issuer" schema:"-"`
			Scopes              []string `mapstructure:"scope" schema:"scope"`
			CodeChallenge       string   `mapstructure:"code_challenge" schema:"code_challenge"`
			CodeChallengeMethod string   `mapstructure:"code_challenge_method" schema:"code_challenge_method"`
			RedirectURI         string   `mapstructure:"redirect_uri" schema:"redirect_uri"`
			State               string   `mapstrucutre:"state" schema:"state"`
		} `mapstructure:"idx"`
	} `mapstructure:"okta"`
}

type ConfigSetter func(*config)

func WithClientID(clientID string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientID = clientID
	}
}

func WithClientSecret(clientSecret string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientSecret = clientSecret
	}
}

func WithIssuer(issuer string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Issuer = issuer
	}
}

func WithScopes(scopes []string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Scopes = scopes
	}
}

func WithCodeChallenge(codeChallenge string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.CodeChallenge = codeChallenge
	}
}

func WithCodeChallengeMethod(codeChallengeMethod string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.CodeChallengeMethod = codeChallengeMethod
	}
}

func WithRedirectURI(redirectURI string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.RedirectURI = redirectURI
	}
}

func WithState(state string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.State = state
	}
}

// ReadConfig reads config from file and environment variables
// Config file should be placed either in project root dir or in $HOME/.okta/
func ReadConfig(config interface{}, opts ...viper.DecoderConfigOption) error {
	v := viper.New()
	v.SetConfigName("okta")
	v.AddConfigPath("$HOME/.okta/")                    // path to look for the config file in
	v.AddConfigPath(".")                               // path to look for config in the working directory
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // replace default viper delimiter for env vars
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)
	err := v.ReadInConfig()
	if err != nil {
		return fmt.Errorf("failed to read from config file: %v", err)

	}
	err = v.Unmarshal(config, opts...)
	if err != nil {
		return fmt.Errorf( "failed to parse configuration: %v", err)
	}
	return nil
}
