package oktaIdentityEngine

import "time"

type OIEResponse struct {
	StateHandle string
	Version     string
	ExpiresAt   time.Time
	Intent      string
}

type OktaIdentityEngineResponse interface {
	remediation()
}
