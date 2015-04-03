The authorization response SNAC is sent by the OSCAR server in response to an AuthRequestSnac during InitialAuthentication. This command is the last command sent on the authentication connection. This packet has two forms.

### Successful login ###

When authentication succeeds, the packet will have the following structure:

[[Include(/Format/Success)]]

`screenname` is your screenname, formatted in the way that other buddies see it: if you log in as "joustacular" but you registered as "Joust Acu LAR", `screenname` will contain "Joust Acu LAR".

`server` is a string in the form "1.2.3.4:5190". This is the IP address and port number you should use to connect to the "main" OSCAR connection (also known as the basic online service server, or BOS server). `cookie` is the FLAP cookie you should use when connecting. See LoggingIn for details.

`email` is the email address currently registered for the screenname. `regStatus` is a number 1-3 describing the user's registration visiblity status. Using the words of AIM's preferences dialog, the values mean the following things:

| `regStatus` | "Users who know my screenname can find out..." |
|:------------|:-----------------------------------------------|
| 0x0001 |  "Nothing about me." |
| 0x0002 | "Only that I have an account." |
| 0x0003 | "My screenname." |

The values of `email` and `regStatus` as well as the official format of the user's screenname (`screenname`) can be modified using the AccountAdmin features of the protocol.

### Failed login ###

When authentication has failed, the packet will have the following structure:

[[Include(/Format/Failure)]]

In this case, `errorCode` will be an error code describing why authorization failed. Known error codes are as follows:

| `errorCode` | Meaning | Tips |
|:------------|:--------|:-----|
| 0x0005 | Invalid screenname or wrong password | If you know the screenname and password are correct, maybe your password hash algorithm code is broken |
| 0x0011 | Account has been suspended temporarily | Probably due to abuse |
| 0x0014 | Account temporarily unavailable | I don't know when this is used |
| 0x0018 | Connecting too frequently | Try waiting a few minutes to reconnect - AIM recommends 10 minutes |
| 0x001c | Client software is too old to connect | Try changing your ClientVersionInfo block to match a newer version of AIM |

`errorUrl` is supposed to be a URL that helps you figure out the problem. In my experience, however, it is always "http://www.aol.com".