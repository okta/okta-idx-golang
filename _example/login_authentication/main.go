package main

/*
This is a simple example to experiment with modifying the idx client code.  The
example will load up the local files as the `idx` package.  Running `go mod
tidy` may be required to allow the go runner to execute without errors. Be sure
app is granted with Interactive Code grant type.

export OKTA_IDX_ISSUER=https://example.com
export OKTA_IDX_CLIENTSECRET=_CHANGE_TO_CORRECT_VALUE
export OKTA_IDX_SCOPES=openid,profile,email,offline_access
export OKTA_IDX_REDIRECTURI=http://localhost:8080/login/callback
export OKTA_IDX_CLIENTID=_CHANGE_TO_ASSOCIATED_APP_ID_

export EXAMPLE_IDENTIFIER=auser@example.com
export EXAMPLE_PASSWORD=changeme

go run main.go
*/

import (
	"context"
	"fmt"
	"idx"
	"log"
	"os"
)

func main() {
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

	fmt.Printf("authenticated? %t\n", lr.IsAuthenticated())
}
