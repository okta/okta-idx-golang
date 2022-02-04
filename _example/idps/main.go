package main

/*
This is a simple example to experiment with modifying the idx client code.  The
example will load up the local files as the `idx` package.  Running `go mod
tidy` may be required to allow the go runner to execute without errors. Be sure
app is granted with Interactive Code grant type. And there are routing rules to
expose the identity providers. Also that `okta.idps.read` is granted on the
Okta API Scopes.


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
