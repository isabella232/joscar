Authenticating with the login server (also called the authentication server or authorization server) is the first step to connecting to AOL Instant Messenger. Normally, the login server is "login.oscar.aol.com", and a connection may be made to it on any port.

The login server connection is a FlapConnection like any other OSCAR connection. One difference, however, is that no FLAP cookie is sent in the initial channel-1 FLAP command.

### Getting the authentication key ###

Upon connecting and exchanging FLAP version numbers, the AIM client should send a KeyRequestSnac packet:

[[Include(KeyRequestSnac/Format)]]

`screenname` should be the user's screenname. As of this writing, I do not know what the 0x004b and 0x005a TLV's do; AIM 5.2 sends them, so you should too. 5.5 does not send either of these TLVs, but it does send a new unknown:  0x004c (according to Ethereal), so I'm willing to bet this is a version marker, but that doesn't explain the older 0x005a. It appears that you don't need to send any of these TLVs though.

In response, the server should send a KeyResponseSnac as a SnacResponse:

[[Include(KeyResponseSnac/Format)]]

`len` is the length of `key`, in bytes. This key will be used to encode the user's password in the authorization request packet.

### Logging in ###

The second step of authentication is actually sending your username, password, and some other values. The password isn't sent in plain text, however; in fact, it's not sent at all. Instead, an MD5 hash of it and some other data is used. For more information, see LoginPasswordHash. The format of the AuthRequestSnac is as follows:

[[Include(AuthRequestSnac/Format)]]

`screenname` is the user's screenname. `country` is a country code, like "us". `lang` is a language code, like "en". `encryptedPass` is the encrypted password data.

#### Successful login ####

If successful, the server will send an AuthResponseSnac as a SnacResponse:

[[Include(AuthResponseSnac/Format/Success)]]

`screenname` is your screenname, formatted in the way that other buddies see it: if you log in as "joustacular" but you registered as "Joust Acu LAR", `screenname` will contain "Joust Acu LAR".

`server` is a string in the form "1.2.3.4:5190". This is the IP address and port number you should use to connect to the "main" OSCAR connection (also known as the basic online service server, or BOS server). `cookie` is the FLAP cookie you should use when connecting. See LoggingIn for details.

`email` is the email address currently registered for the screenname. `regStatus` is a number 1-3 describing the user's registration visiblity status. Using the words of AIM's preferences dialog, the values mean the following things:

| `regStatus` | "Users who know my screenname can find out..." |
|:------------|:-----------------------------------------------|
| 0x0001 |  "Nothing about me." |
| 0x0002 | "Only that I have an account." |
| 0x0003 | "My screenname." |

The values of `email` and `regStatus` as well as the official format of the user's screenname (`screenname`) can be modified using the AccountAdmin features of the protocol.

#### Failed login ####

If authorization fails, however, the same AuthResponseSnac SnacResponse will be sent, but with different data:

[[Include(AuthResponseSnac/Format/Failure)]]

`errorCode` will be an error code describing why authorization failed. Known error codes are as follows:

| `errorCode` | Meaning | Tips |
|:------------|:--------|:-----|
| 0x0005 | Invalid screenname or wrong password | If you know the screenname and password are correct, maybe your password hash algorithm code is broken |
| 0x0011 | Account has been suspended temporarily | Probably due to abuse |
| 0x0014 | Account temporarily unavailable | I don't know when this is used |
| 0x0018 | Connecting too frequently | Try waiting a few minutes to reconnect - AIM recommends 10 minutes |
| 0x001c | Client software is too old to connect | Try changing your ClientVersionInfo block to match a newer version of AIM |

`errorUrl` is supposed to be a URL that helps you figure out the problem. In my experience, however, it is always "http://www.aol.com".

### Conclusion ###

After authentication either succeeds or fails as described above, the login server connection has no more purpose and should be closed immediately. If login succeeded, a connection should be made to the main OSCAR server provided in the authorization response.