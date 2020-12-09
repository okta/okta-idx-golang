[<img src=".github/images/logo.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![GitHub Workflow Status](https://github.com/okta/okta-identity-engine-golang/workflows/CI/badge.svg)](https://github.com/okta/okta-identity-engine-golang/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/okta/okta-identity-engine-golang?style=flat-square)](https://goreportcard.com/report/github.com/okta/okta-identity-engine-golang)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/okta/okta-identity-engine-golang)](https://pkg.go.dev/mod/github.com/okta/okta-identity-engine-golang)

# Okta IDX - Golang

This repository contains the Okta IDX SDK for Golang. This SDK can be used in your server-side code to assist in authenticating users against the Okta IDX.

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
IDXClient, err := NewIDXClient(
    WithClientId("{YOUR_CLIENT_ID}"),
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


[okta-library-versioning]: https://developer.okta.com/code/library-versions/
[github-issues]: https://github.com/okta/okta-identity-engine-golang/issues
[developer-edition-signup]: https://developer.okta.com/signup
[support-email]: mailto://support@okta.com