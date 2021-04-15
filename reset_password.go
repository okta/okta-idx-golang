package idx

import (
	"context"
	"fmt"
	"strings"
)

func (c *Client) InitPasswordReset(ctx context.Context, ir *IdentifyRequest) (*AuthenticationResponse, error) {
	idxContext, err := c.Interact(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.Introspect(context.TODO(), idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("identify")
	if err != nil {
		return nil, err
	}
	identify := []byte(fmt.Sprintf(`{
                "identifier": "%s",
                "rememberMe": %t
            }`, ir.Identifier, ir.RememberMe))
	resp, err = ro.Proceed(ctx, identify)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticatorEnrollment == nil {
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' field is missing from the response")
	}
	resp, err = resp.CurrentAuthenticatorEnrollment.Value.Recover.Proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	authenticationResponse := &AuthenticationResponse{
		idxContext:           idxContext,
		authenticationStatus: AuthStatusUnhandled,
	}
	_, _, err = resp.authenticatorOption("select-authenticator-authenticate", "Email")
	if err == nil {
		authenticationResponse.authenticationStatus = AuthStatusEmailVerification
	}
	return authenticationResponse, nil
}

func (c *Client) VerifyEmailOnPasswordReset(ctx context.Context, idxContext *Context) (*AuthenticationResponse, error) {
	resp, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticatorEnrollment == nil {
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' field is missing from the response")
	}
	resp, err = resp.CurrentAuthenticatorEnrollment.Value.Recover.Proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Email")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	_, err = ro.Proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	return &AuthenticationResponse{
		idxContext:           idxContext,
		authenticationStatus: AuthStatusEmailConfirmation,
	}, nil
}

func (c *Client) ConfirmEmailOnPasswordReset(ctx context.Context, idxContext *Context, code string) (*AuthenticationResponse, error) {
	resp, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"passcode": "%s"
				}
			}`, strings.TrimSpace(code)))
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	authenticationResponse := &AuthenticationResponse{
		idxContext:           idxContext,
		authenticationStatus: AuthStatusUnhandled,
	}
	_, err = resp.remediationOption("reset-authenticator")
	if err == nil {
		authenticationResponse.authenticationStatus = AuthStatusNewPassword
	}
	return authenticationResponse, nil
}

func (c *Client) SetNewPasswordOnPasswordReset(ctx context.Context, idxContext *Context, password string) (*AuthenticationResponse, error) {
	resp, err := c.Introspect(ctx, idxContext)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("reset-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(`{
		"credentials": {
			"passcode": "` + strings.TrimSpace(password) + `"
		}
	}`)
	resp, err = ro.Proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	authenticationResponse := &AuthenticationResponse{
		idxContext:           idxContext,
		authenticationStatus: AuthStatusUnhandled,
	}
	if resp.LoginSuccess() {
		exchangeForm := []byte(`{
			"client_secret": "` + c.ClientSecret() + `",
			"code_verifier": "` + idxContext.CodeVerifier() + `"
		}`)
		tokens, err := resp.SuccessResponse.ExchangeCode(ctx, exchangeForm)
		if err != nil {
			return nil, err
		}
		authenticationResponse.token = tokens
		authenticationResponse.authenticationStatus = AuthStatusSuccess
	}
	return authenticationResponse, nil
}
