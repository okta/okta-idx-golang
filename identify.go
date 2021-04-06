package idx

import (
	"context"
	"fmt"
)

type IdentifyRequest struct {
	Identifier string `json:"identifier"`
	RememberMe bool   `json:"remember_me"`
}

func (r *Response) Identify(ctx context.Context, ir *IdentifyRequest) (*Response, error) {
	ro, err := r.remediationOption("identify")
	if err != nil {
		return nil, err
	}
	identify := []byte(fmt.Sprintf(`{
                "identifier": "%s",
                "rememberMe": %t
            }`, ir.Identifier, ir.RememberMe))
	return ro.Proceed(ctx, identify)
}
