The location rights (user info parameters) SNAC is sent by the OSCAR server in response to a LocationRightsRequestSnac while LoggingIn. The format of this packet is:

[[Include(/Format)]]

`maxInfoLen` defines the maximum length, in bytes, that a user info (user profile) or away message can be. This, unlike ICBM parameters, cannot be modified. As of this writing (Oct. 11, 2003), the value sent is 1024 bytes.