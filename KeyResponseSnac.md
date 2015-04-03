The key response SNAC is sent by the OSCAR server in response to a KeyRequestSnac. It contains an authentication key to the client for use in encrypting his password during the login process. For more details, see InitialAuthentication.

[[Include(/Format)]]

`len` is the length of `key`, in bytes. This key will be used to encode the user's password in the authorization request packet.