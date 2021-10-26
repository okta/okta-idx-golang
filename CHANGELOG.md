# Changelog

## v0.2.2
- Client's Interact method is public.
- Attributes on IDX Context are public.
- New Client method RedeemInteractionCode that returns an AccessToken.

## v0.2.1
- Makes public Config type.
- Adds a public Config() method access configuration variables on client.

## v0.2.0
- Refine configuration semantics.

## v0.1.0-beta.2
- Interact now returns `Context` struct
- Introspect requires a second parameter, `state *string`. This can be `nil` if you want the library to create a state for you.

- `Context.interactionHandle` stores a string for the interaction handle. Can be retrieved with `Context.InteractionHandle()`
- `Context.state` stores the state string. This can be set during `Interact` as the second parameter, and can be retrieved with `Context.State()`
- `Context.codeVerifier` stores the codeVerifier to be used during the token exchange. The library generates PKCE data for you and this can be accessed with `Context.CodeVerifier()`

## v0.1.0-beta.1

- Initial version with basic functionality
