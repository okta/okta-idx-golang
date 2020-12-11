[<img src=".github/images/logo.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![GitHub Workflow Status](https://github.com/okta/okta-identity-engine-golang/workflows/CI/badge.svg)](https://github.com/okta/okta-identity-engine-golang/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/okta/okta-identity-engine-golang?style=flat-square)](https://goreportcard.com/report/github.com/okta/okta-identity-engine-golang)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/okta/okta-identity-engine-golang)](https://pkg.go.dev/mod/github.com/okta/okta-identity-engine-golang)

# Okta IDX - Golang

This repository contains the Okta IDX SDK for Golang. This SDK can be used in your server-side code to assist in authenticating users against the Okta IDX.


> :grey_exclamation: The use of this SDK requires you to be a part of our limited general availability (LGA) program with access to Okta Identity Engine. If you want to request to be a part of our LGA program for Okta Identity Engine, please reach out to your account manager. If you do not have an account manager, please reach out to oie@okta.com for more information.

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.x     | :warning: In Development           |

The latest release can always be found on the [releases page][github-releases].


## Need help?

If you run into problems using the SDK, you can

 - Ask questions on the [Okta Developer Forums][devforum]
 - Post [issues on GitHub][github-issues] (for code errors)


## Getting started

### Prerequisites
You will need:
 - An Okta account, called an organization. (Sign up for a free [developer organization][developer-edition-signup] if you need one)
 - Access to the Okta Identity Engine feature. Currently, an early access feature. Contact [support@okta.com][support-email] for more information.

## Usage Guide
These examples will help you understand how to use this library.

Once you initialize a `Client`, you can call methods to make requests to the Okta IDX API.

### Create the Client
```go
client, err := NewClient(
    WithClientID("{YOUR_CLIENT_ID}"),
    WithClientSecret("{YOUR_CLIENT_SECRET}"), // Required for confidential clients.
    WithIssuer("{YOUR_ISSUER}"), // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    WithScopes([]string{"openId"}), // Must include at least `openId`
    WithCodeChallenge("{PKCE_CODE_CHALLENGE}"), // Base64url_encoded(sha256({code_verifier}))
    WithCodeChallengeMethod("S256"), // PKCE challenge method, only supports S256
    WithRedirectURI("{YOUR_REDIRECT_URI}"), // Must match the redirect uri in client app settings/console
    WithState("{APP_STATE}"),
)
if err != nil {
    fmt.Errorf("could not create a new IDX Client", err)
}
```

### Get Interation Handle
```go
interactionHandle, err := IDXClient.Interact(context.TODO())
if err != nil {
    fmt.Errorf("retriving an interaction handle failed", err)
}
```

### Using Interaction Handle for Introspect
```go
introspectResponse, err := IDXClient.Introspect(context.TODO(), interactionHandle)
if err != nil {
    fmt.Errorf("could not introspect IDX", err)
}
```

## Configuration Reerence
This library looks for the configuration in the following sources:

1. An okta.yaml file in a .okta folder in the current user's home directory (~/.okta/okta.yaml or %userprofile%\.okta\okta.yaml)
2. An okta.yaml file in a .okta folder in the application or project's root directory
3. Environment variables
4. Configuration explicitly passed to the constructor (see the example in [Getting started](#getting-started))

Higher numbers win. In other words, configuration passed via the constructor will override configuration found in environment variables, which will override configuration in okta.yaml (if any), and so on.

### Config Properties
| Yaml Path             | Environment Key       | Description                                                                                                          |
|-----------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------|
| okta.idx.issuer       | OKTA_IDX_ISSUER       | The issuer of the authorization server you want to use for authentication.                                           |
| okta.idx.clientId     | OKTA_IDX_CLIENTID     | The client ID of the Okta Application.                                                                               |
| okta.idx.clientSecret | OKTA_IDX_CLIENTSECRET | The client secret of the Okta Application. Required with confidential clients                                        |
| okta.idx.scopes       | OKTA_IDX_SCOPES       | The scopes requested for the access token.                                                                           |
| okta.idx.redirectUri  | OKTA_IDX_REDIRECTURI  | For most cases, this will not be used, but is still required to supply. You can put any configured redirectUri here. |

#### Yaml Configuration
The configuration would be expressed in our okta.yaml configuration for SDKs as follows:

```yaml
okta:
  idx:
    issuer: {issuerUrl}
    clientId: {clientId}
    clientSecret: {clientSecret}
    scopes:
    - {scope1}
    - {scope2}
    redirectUri: {configuredRedirectUri}
```

#### Environment Configuration
The configuration would be expressed in environment variables for SDKs as follows:
```env
OKTA_IDX_ISSUER
OKTA_IDX_CLIENTID
OKTA_IDX_CLIENTSECRET
OKTA_IDX_SCOPES
OKTA_IDX_REDIRECTURI
```


[okta-library-versioning]: https://developer.okta.com/code/library-versions/
[github-issues]: https://github.com/okta/okta-identity-engine-golang/issues
[developer-edition-signup]: https://developer.okta.com/signup
[support-email]: mailto://support@okta.com