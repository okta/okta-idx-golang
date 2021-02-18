# Changelog

## v0.1.0-beta.2
- Interact now returns `IdxContext` struct
- Introspect requires a second parameter, `state *string`. This can be `nil` if you want the library to create a state for you.

- `IdxContext.interactionHandle` stores a string for the interaction handle. Can be retrieved with `IdxContext.GetInteractionHandle()`
- `IdxContext.state` stores the a state string. This can be set during `Interact` as the second parameter, and can be retrieved with `IdxContext.GetState()`
- `IdxContext.codeVerifier` stores the codeVerifier to be used during the token exchange. The library generates PKCE data for you and this can be accessed with `IdxContext.GetCodeVerifier()`

## v0.1.0-beta.1

- Initial version with basic functionality