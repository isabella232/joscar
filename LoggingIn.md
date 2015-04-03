Logging into the basic online service (BOS) server after InitialAuthentication is a complicated process. The BOS server's hostname and port number was provided during InitialAuthentication; once connected and after sending the login cookie (see FlapConnection for details), a series of SNAC command exchanges are made.

This page is meant to familiarize you with the login process of AIM 5.2 and possibly provide a "quick start" for your client to be able to log in. The login process involves many other areas of the protocol; these areas are more completely documented elsewhere in this documentation project.

## Initial SNAC setup ##

Once the FLAP connection has been initialized (you have sent your FLAP cookie and the server has sent its FLAP version), the server will send a "server ready" SNAC packet:

[[Include(ServerReadySnac/Format)]]

The SNAC data will contain a list of the SNAC families that the server supports, as a sequence of UnsignedShort``s. Normally, the BOS server will send that it supports the families 0x1, 0x2, 0x3, 0x4, 0x6, 0x8, 0x9, 0xa, 0xb, 0xc, 0x13, 0x15. The SnacCommand documentation describes what these families are.

Next, you should respond with a client SNAC family version information command, containing a list of the SNAC family versions your client supports (The request id must be 0 for this SNAC):

[[Include(ClientVersionsSnac/Format)]]

It is important to send the latest SNAC family versions to enable access to newer protocol features. The SNAC family version values sent by AIM 5.5.3415 beta are as follows:

| Family | 0x01 | 0x02 | 0x03 | 0x04 | 0x06 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x13 | 0x15 |
|:-------|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|
| Version | 4 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | ''N/A'' | 3 | ''N/A'' |

''N/A'' indicates that the AIM 5.5.3415 beta does not support the given family.

In response (though not as a SnacResponse), the server sends a server SNAC versions packet in the very same format:

[[Include(ServerVersionsSnac/Format)]]

As of this writing (Oct. 11, 2003), the SNAC family versions sent by the official AIM server are as follows:

| Family | 0x01 | 0x02 | 0x03 | 0x04 | 0x06 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x13 | 0x15 |
|:-------|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|
| Version | 4 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 4 | 1 |

## Rate limiting information ##

Next, the client should request rate-limiting information. This is done with a RateInfoRequestSnac:

[[Include(RateInfoRequestSnac/Format)]]

The server should send back a RateInfoSnac as a SnacResponse containing lots of rate limiting information:

[[Include(RateInfoSnac/Format)]]

For more information on rate classes, see RateLimiting. In response to this, the client must send a rate acknowledgement packet (RateAckSnac):

[[Include(RateAckSnac/Format)]]

The `rateClassX` values should be the `rateClass` values given to you by the server in the previous rate information packet.

After the rate class acknowledgement packet is sent, the rate limiting values given by the server are in effect.

## ICBM parameters ##

Next, the client must send a request for your IcbmParameterInfo. ICBM parameters define limits and capabilities related to InstantMessages and RendezvousProtocol. The IcbmParamRequestSnac packet looks like the following:

[[Include(IcbmParamRequestSnac/Format)]]

The server will send an IcbmParamInfoSnac (as a SnacResponse) containing your current ICBM parameter info:

[[Include(IcbmParamInfoSnac/Format)]]

`paramInfo` will contain the client's current ICBM parameter information. Your ICBM parameter information is set to the default each time you connect, and the defaults are rather restrictive. As of this writing (Oct. 11, 2003), the defaults sent by the official AIM server are as follows:

| Field | Default value |
|:------|:--------------|
| `maxChannel` | 2 |
| `flags` | 0x00000002 | 0x00000001 |
| `maxMsgLen` | 512 bytes |
| `maxSenderWarning` | 99.9% |
| `maxReceiverWarning` | 99.9% |
| `minMsgInterval` | 1000 ms |

AIM 5.2 changes these to the following values, and you probably want to as well:

| Field | Suggested value | Reason for change |
|:------|:----------------|:------------------|
| `maxChannel` | 0 ''(see below)'' |  |
| `flags` | `flags` | 0x00000008 | Enables typing notification |
| `maxMsgLen` | 8000 bytes | Enables longer messages |
| `maxSenderWarning` | 99.9% |  |
| `maxReceiverWarning` | 99.9% |  |
| `minMsgInterval` | 0 ms | Allows messages to be sent as fast as rate limiting allows |

For more details on what these values do, see IcbmParameterInfo and InstantMessages.

To change your parameter information, you send a SetParamInfoSnac:

[[Include(SetParamInfoSnac/Format)]]

> /!\ Any of the parameter information fields can be changed except for `maxChannel`. When sending a set ICBM parameter information packet, the `maxChannel` field must be 0.

## User information (location rights) ##

Next, the client should request a set of user information parameters. User information parameters (also known as "location rights") determine limits associated with your user information.

To request user information parameters, the client should send a user information parameter request packet (LocationRightsRequestSnac):

[[Include(LocationRightsRequestSnac/Format)]]

The server will send a user information parameters SnacResponse:

[[Include(LocationRightsSnac/Format)]]

`maxInfoLen` defines the maximum length, in bytes, that a user info (user profile) or away message can be. This, unlike ICBM parameters, cannot be modified. As of this writing (Oct. 11, 2003), the value sent is 1024 bytes.

Now that you know the maximum length, your client may wish to set a user info and (if the user was away before connecting) an away message.

## Server-stored information ##

Next, the client should request server-stored information parameters (also known as SSI rights). These determine limits on various aspects of server-stored information. To request these parameters, you can send a SSI rights request:

[[Include(SsiRightsRequestSnac/Format)]]

The server will send a SsiRightsSnac as a SnacResponse:

[[Include(SsiRightsSnac/Format)]]

`maxN` is the maximum number of SSI items of type `N` that can be stored.

As of this writing (Oct. 12, 2003), the maximum number of items of each type allowed on AOL's AIM servers are as follows (the table is split into two tables):

| Type | 0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x5 | 0x6 | 0x7 | 0x8 | 0x9 | 0xa | 0xb | 0xc | 0xd | 0xe | 0xf |
|:-----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|
| Max. | 400 | 61 | 200 | 200 | 1 | 1 | 150 | 12 | 12 | 0 | 50 | 50 | 0 | 0 | 0 | 0 |

| Type | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 |
|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|
| Max. | 0 | 1 | 0 | 0 | 10 | 1 | 40 | 1 | 10 |

This means that the user can have 400 buddies, 60 groups (one is reserved as the "master group") 200 blocks, and 200 allows. Many of the other types' purposes are unknown (they are not used by AIM 5.2).

At this point, the client should request the server-stored data. This can be done in two ways; here only one will be documented. See ServerStoredInfo for details. The SsiDataRequestSnac looks like this:

[[Include(SsiDataRequestSnac/Format)]]

The server will send a SsiDataSnac as a SnacResponse:

[[Include(SsiDataSnac/Format)]]

As of this writing, `ssiVersion` is always 0. `itemCount` is the number of SsiItemBlock``s sent. `lastMod` is the date at which the data were last modified. For more details on server-stored information, see ServerStoredInfo.

Next, your client should make any modifications to the buddy list it needs to do before signing on. AIM 5.2 can make a number of modifications here, including fixing a corrupt buddy list (see BuddyListValidity for details). Your client may also wish to block a buddy the user blocked while disconnected, change privacy settings, and so on.

After (optionally) modifying the buddy list, the client should send an ActivateSsiSnac:

[[Include(ActivateSsiSnac/Format)]]

This will "activate" the server-stored data for the session. Once the server-stored data are activated for the session, they cannot be deactivated. (This means that future changes to the server-stored data are reflected immediately.) Activating the server-stored data "applies" the data to your session, blocking users stored as blocked items, setting your privacy settings to the values set in the privacy item, and so on.

Server-stored data do not need to be activated, but means of blocking users, setting privacy settings, and modifying the buddy list without SSI are not documented in this documentation project.

## Finishing up ##

Next, the client may wish to see its own user information (UserInfo). This contains important information such as the client's warning level. The MyInfoRequestSnac looks like this:

[[Include(MyInfoRequestSnac/Format)]]

The server will respond to this with a YourInfoSnac as a SnacResponse:

[[Include(YourInfoSnac/Format)]]

`userInfo` is a user information block for the client user; this is what your client's buddies will see in BuddyStatusSnac``s for the user.

Finally, your client is ready to sign on. The ClientReadySnac indicates to the server that you are ready to appear as "online" and that all pre-signon setup is complete. This command also contains more detailed information than given earlier about the client's capabilities, in the form of AOL software module versions:

[[Include(ClientReadySnac/Format)]]

The SNAC contains a series of SnacFamilyVersionsBlock``s, one for each SNAC family supported.

Since your client does not use the AIM modules ("tools"), it should probably emulate the values sent by the official AIM clients. As of AIM 5.5.3415 beta, the SNAC family versions and tool versions sent are as follows:

| Family | Version | Tool ID | Tool version |
|:-------|:--------|:--------|:-------------|
| 0x0001 | 0x0004 | 0x0010 | 0x0801 |
| 0x0002 | 0x0001 | 0x0110 | 0x0801 |
| 0x0003 | 0x0001 | 0x0110 | 0x0801 |
| 0x0004 | 0x0001 | 0x0110 | 0x0801 |
| 0x0006 | 0x0001 | 0x0110 | 0x0801 |
| 0x0008 | 0x0001 | 0x0104 | 0x0001 |
| 0x0009 | 0x0001 | 0x0110 | 0x0801 |
| 0x000a | 0x0001 | 0x0110 | 0x0801 |
| 0x000b | 0x0001 | 0x0104 | 0x0001 |
| 0x0013 | 0x0003 | 0x0110 | 0x0801 |

The server will respond to this with several commands (including a BuddyStatusSnac for every buddy who is online) which are not documented in this section. Your client is now online.
