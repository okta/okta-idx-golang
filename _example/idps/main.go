package main

/*
This is simple example to fiddle with the code if experimenting with modifying
the client code.  The example will load up the local files as the idx package.
Might need to `go mod tidy` first to make work. Be sure app is granted
Interactive Code grant type. And there is a routing rules to expose the identity
providers. Also `okta.idps.read` is granted on the Okta API Scopes.

export OKTA_IDX_ISSUER=https://example.com
export OKTA_IDX_CLIENTSECRET=_CHANGE_TO_CORRECT_VALUE
export OKTA_IDX_SCOPES=openid,profile,email,offline_access
export OKTA_IDX_REDIRECTURI=http://localhost:8080/login/callback
export OKTA_IDX_CLIENTID=_CHANGE_TO_ASSOCIATED_APP_ID_

go run main.go
*/

import (
	"context"
	"fmt"
	"idx"
	"log"
)

func main() {
	ctx := context.TODO()
	client, err := idx.NewClient()
	if err != nil {
		log.Fatalf("new client error: %+v\n", err)
	}

	lr, err := client.InitLogin(ctx)
	if err != nil {
		log.Fatalf("init login error: %+v\n", err)
	}

	fmt.Println("Identity Providers configured on my organization:")
	idps := lr.IdentityProviders()
	if len(idps) == 0 {
		fmt.Println("  none :(")

	}
	for _, idp := range idps {
		fmt.Printf("  %s\n", idp.Name)
	}
}
