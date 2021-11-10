[<img src=".github/images/logo.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![GitHub Workflow Status](https://github.com/okta/okta-idx-golang/workflows/CI/badge.svg)](https://github.com/okta/okta-idx-golang/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/okta/okta-idx-golang?style=flat-square)](https://goreportcard.com/report/github.com/okta/okta-idx-golang)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/okta/okta-idx-golang)](https://pkg.go.dev/mod/github.com/okta/okta-idx-golang)

# Okta IDX - Golang

## Introduction

> :grey_exclamation: The use of this SDK requires usage of the Okta Identity
Engine. This functionality is in general availability but is being gradually
rolled out to customers. If you want to request to gain access to the Okta
Identity Engine, please reach out to your account manager. If you do not have an
account manager, please reach out to oie@okta.com for more information.

This library is built for projects in Golang to communicate with Okta as an OAuth 
2.0 + OpenID Connect provider. It works with [Okta's Identity Engine](https://developer.okta.com/docs/concepts/ie-intro/)
to authenticate and register users.

To see this library working in a sample, check out our [Golang Sample
Applications](https://github.com/okta/samples-golang).

## Release status

This library uses semantic versioning and follows Okta's [Library Version
Policy](https://developer.okta.com/code/library-versions/).

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.x     | Beta                               |

The latest release can always be found on the [releases
page](https://github.com/okta/okta-idx-golang/releases).

## Need help?

If you run into problems using the SDK, you can

- Ask questions on the [Okta Developer Forums](https://devforum.okta.com/)
- Post [issues on GitHub](https://github.com/okta/okta-idx-golang/issues) (for
  code errors)

## Getting started

### Prerequisites

You will need:

- An Okta account, called an organization. (Sign up for a free [developer
  organization][developer-edition-signup] if you need one)
- Access to the Okta Identity Engine feature. Currently, an early access
  feature.  Contact [support@okta.com][support-email] for more information.

### Install current release

To install the Okta IDX SDK in your project:

- Create a module file by running go mod init
  - You can skip this step if you already use go mod
- Run go get github.com/okta/okta-idx-golang. This will add the SDK to your
  go.mod file.
- Import the package in your project with import
  "github.com/okta/okta-idx-golang"

## Usage Guide

The [embedded authentication with
SDK](https://github.com/okta/samples-golang/tree/master/identity-engine/embedded-auth-with-sdk)
sample application provides an example making use of the IDX SDK.

### Create the Client

Create a client as implemented [in the sample application's
server](https://github.com/okta/samples-golang/blob/master/identity-engine/embedded-auth-with-sdk/server/server.go#L59-L80).

#### Default Client

Default client will load settings from configuration file (okta.yaml) followed by environment variables, if any are set. Environment variables will override the configuration file. 
See the section [Configuration Reference](#configuration-reference)

```go
idx, err := idx.NewClient()
```

#### Client configured with setters

Setters will override any settings previously set on the underlying default client.

```go
idx, err := idx.NewClientWithSettings(
		idx.WithClientID("0123456789abcdefghij"),
		idx.WithClientSecret("changeme"),
		idx.WithIssuer("https://example.com/oauth2"),
		idx.WithScopes([]string{"openid", "profile", "email", "offline_access"}),
		idx.WithRedirectURI("https://example.com/login/callback")
  )
```

### Login with convenient authentication options

Once login has been initialized the login response provides mechanisms for
various authentication factors.

```go
// establish context here, or use context from/within a caller
ctx := context.TODO()

client, err := idx.NewClient()
if err != nil {
	log.Fatalf("new client error: %+v\n", err)
}

authOpts := idx.AuthenticationOptions{
	UserName: os.Getenv("EXAMPLE_IDENTIFIER"),
	Password: os.Getenv("EXAMPLE_PASSWORD"),
}

lr, err := client.Authenticate(ctx, &authOpts)
if err != nil {
	log.Fatalf("authentication error: %+v\n", err)
}

// is authenticated is a convenience method
fmt.Printf("authenticated? %t\n", lr.IsAuthenticated())

// or query the token directly
if lr.Token() == nil {
  // failed to login
}

// do something, having a token signals identification success
```

### Login with detailed identity request

Once login has been initialized the login response provides mechanisms for
various authentication factors.

```go
// establish context here, or use context from/within a caller
ctx := context.TODO()

lr, err := idx.InitLogin(ctx)

// password authentication
ir := &idx.IdentifyRequest{
		Identifier: r.FormValue("identifier"),
		Credentials: idx.Credentials{
			Password: r.FormValue("password"),
		},
	}

lr, err = lr.Identify(ctx, ir)
if err != nil || lr.Token() == nil {
  // failed to login
}

// do something, having a token signals identification success
```

## Configuration Reference

This library looks for the configuration in the following sources:

1. An okta.yaml file in a .okta folder in the current user's home directory
   (~/.okta/okta.yaml or %userprofile%\.okta\okta.yaml)
2. An okta.yaml file in a .okta folder in the application or project's root
   directory
3. Environment variables
4. Configuration explicitly passed to the constructor (see the example in
   [Getting started](#getting-started))

Higher numbers win. In other words, configuration passed via the constructor
will override configuration found in environment variables, which will override
configuration in okta.yaml (if any), and so on.

### Config Properties

| Yaml Path             | Environment Key       | Description                                                                                                          |
|-----------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------|
| okta.idx.issuer       | OKTA_IDX_ISSUER       | The issuer of the authorization server you want to use for authentication.                                           |
| okta.idx.clientId     | OKTA_IDX_CLIENTID     | The client ID of the Okta Application.                                                                               |
| okta.idx.clientSecret | OKTA_IDX_CLIENTSECRET | The client secret of the Okta Application. Required with confidential clients                                        |
| okta.idx.scopes       | OKTA_IDX_SCOPES       | The scopes requested for the access token. Format yaml: array of values. Format ENV: CSV values                      |
| okta.idx.redirectUri  | OKTA_IDX_REDIRECTURI  | For most cases, this will not be used, but is still required to supply. You can put any configured redirectUri here. |

### Debug/Development Properties

| Environment Key  | Description                                                            |
|------------------|------------------------------------------------------------------------|
| DEBUG_IDX_CLIENT | Using httputil all http requests and responses are println'd to stdout |

#### Yaml Configuration

The configuration could be expressed in our okta.yaml configuration for SDK as follows:

```yaml
okta:
  idx:
    issuer: { issuerUrl }
    clientId: { clientId }
    clientSecret: { clientSecret }
    scopes:
      - { scope1 }
      - { scope2 }
    redirectUri: { configuredRedirectUri }
```

#### Environment Configuration

The configuration could also be expressed via environment variables for SDK as follows:

```env
OKTA_IDX_ISSUER=https://myorg.okta.com/oauth2/default
OKTA_IDX_CLIENTID=0123456789abcdefghij
OKTA_IDX_CLIENTSECRET=changme
OKTA_IDX_SCOPES=openid,profile,email,offline_access
OKTA_IDX_REDIRECTURI=https://myorg.okta.com/login/callback
```

[okta-library-versioning]: https://developer.okta.com/code/library-versions/

[github-issues]: https://github.com/okta/okta-idx-golang/issues

[developer-edition-signup]: https://developer.okta.com/signup

[support-email]: mailto://support@okta.com
