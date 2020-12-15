[<img src=".github/images/logo.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![GitHub Workflow Status](https://github.com/okta/okta-identity-engine-golang/workflows/CI/badge.svg)](https://github.com/okta/okta-identity-engine-golang/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/okta/okta-identity-engine-golang?style=flat-square)](https://goreportcard.com/report/github.com/okta/okta-identity-engine-golang)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/okta/okta-identity-engine-golang)](https://pkg.go.dev/mod/github.com/okta/okta-identity-engine-golang)

# Okta IDX - Golang

This repository contains the Okta IDX SDK for Golang. This SDK can be used in your server-side code to assist in authenticating users against the Okta IDX.


> :grey_exclamation: The use of this SDK requires the usage of the Okta Identity Engine. This functionality is in general availability but is being gradually rolled out to customers. If you want to request to gain access to the Okta Identity Engine, please reach out to your account manager. If you do not have an account manager, please reach out to oie@okta.com for more information.
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
    WithClientSecret("{YOUR_CLIENT_SECRET}"),   // Required for confidential clients.
    WithIssuer("{YOUR_ISSUER}"),                // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    WithScopes([]string{"openid", "profile"}),  // Must include at least `openid`. Include `profile` if you want to do token exchange
    WithRedirectURI("{YOUR_REDIRECT_URI}"),     // Must match the redirect uri in client app settings/console
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

#### Get New Tokens (access_token/id_token/refresh_token)
In this example, the sign-on policy has no authenticators required.
> Note: Steps to identify the user might change based on the Org configuration.

```go
var response *Response

client, err := NewClient(
    WithClientID("{CLIENT_ID}"),
    WithClientSecret("{CLIENT_SECRET}"),        // Required for confidential clients.
    WithIssuer("{ISSUER}"),                     // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    WithScopes([]string{"openid", "profile"}),  // Must include at least `openid`. Include `profile` if you want to do token exchange
    WithRedirectURI("{REDIRECT_URI}"),          // Must match the redirect uri in client app settings/console
)
if err != nil {
    panic(err)
}

_, err = client.Interact(context.TODO())
if err != nil {
    panic(err)
}

interactHandle, err := client.Interact(context.TODO())
if err != nil {
    panic(err)
}

response, err = client.Introspect(context.TODO(), interactHandle)
if err != nil {
    panic(err)
}

for !response.LoginSuccess() {
    for _, remediationOption := range response.Remediation.RemediationOptions {

        switch remediationOption.Name {
        case "identify":
            identify := []byte(`{
                    "identifier": "foo@example.com",
                    "rememberMe": false
                }`)

            response, err = remediationOption.Proceed(context.TODO(), identify)
            if err != nil {
                panic(err)
            }

        case "challenge-authenticator":
            credentials := []byte(`{
                    "credentials": {
                    "passcode": "Abcd1234"
                    }
                }`)

            response, err = remediationOption.Proceed(context.TODO(), credentials)

            if err != nil {
                panic(err)
            }

        default:
            fmt.Printf("%+v\n", response.Remediation)
            panic("could not handle")
        }

    }
}

// These properties are based on the `successWithInteractionCode` object, and the properties that you are required to fill out
exchangeForm := []byte(`{
    "client_secret": "` + client.config.Okta.IDX.ClientSecret + `", // This should be available off the client config this way
    "code_verifier": "` + string(client.GetCodeVerifier()) + `" // We generate your code_verfier for you and store it in the client struct. You can gain access to it through the method `GetCodeVerifier()` which willr eturn a string
}`)
tokens, err := response.SuccessResponse.ExchangeCode(context.Background(), exchangeForm)
if err != nil {
    panic(err)
}

fmt.Printf("%+v\n", tokens)
fmt.Printf("%+s\n", tokens.AccessToken)
fmt.Printf("%+s\n", tokens.IDToken)
```

#### Cancel the OIE Transaction and Start a New One
In this example the Org is configured to require email as a second authenticator. After answering password challenge, a cancel request is send right before answering the email challenge.

```go
var response *Response

client, err := NewClient(
    WithClientID("{CLIENT_ID}"),
    WithClientSecret("{CLIENT_SECRET}"),       // Required for confidential clients.
    WithIssuer("{ISSUER}"),                    // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    WithScopes([]string{"openid", "profile"}), // Must include at least `openid`. Include `profile` if you want to do token exchange
    WithRedirectURI("{REDIRECT_URI}"),         // Must match the redirect uri in client app settings/console
)
if err != nil {
    panic(err)
}

_, err = client.Interact(context.TODO())
if err != nil {
    panic(err)
}

interactHandle, err := client.Interact(context.TODO())
if err != nil {
    panic(err)
}

response, err = client.Introspect(context.TODO(), interactHandle)
if err != nil {
    panic(err)
}

for _, remediationOption := range response.Remediation.RemediationOptions {

    if remediationOption.Name == "identify" {
        identify := []byte(`{
                "identifier": "foo@example.com",
                "rememberMe": false
            }`)

        response, err = remediationOption.Proceed(context.TODO(), identify)
        if err != nil {
            panic(err)
        }
    } else {
        panic("we expected an `identify` option, but did not see one.")
    }
}

for _, remediationOption := range response.Remediation.RemediationOptions {

    if remediationOption.Name == "challenge-authenticator" {
        credentials := []byte(`{
                "credentials": {
                "passcode": "Abcd1234"
                }
            }`)

        response, err = remediationOption.Proceed(context.TODO(), credentials)

        if err != nil {
            panic(err)
        }
    } else {
        panic("we expected an `identify` option, but did not see one.")
    }
}

response, err := response.Cancel(context.TODO())
if err != nil {
    panic(err)
}

// From now on, you can use response to continue with a new flow. You will notice here that you have a new `stateHandle` which signals a new flow. Your `interaction_handle` will remain the same.
```

### Check Remediation Options
```go
// check remediation options to continue the flow
options := idxResponse.Remediation.RemediationOptions
option := options[:0]
formValues := option.Form()

```

### Cancel Flow
You can cancel the current flow at any time. This will invalidate the current `stateHandle` and return a new remediation response with a new `stateHandle`.
```go
idxResponse, err := response.Cancel(context.TODO())
```

### Get Raw Response
At times, you may need to access the full response. This can be done with any IDX response:
```go
raw := response.Raw()
```

### Determine When Login is Successful
At any point during the login, you may be finished with remedidation. For this, we provide a `LoginSuccess()` method you can check which will return a boolean.
```go
isLoginSuccess := response.LoginSuccess()
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