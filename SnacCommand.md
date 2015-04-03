# SNAC commands #

The great majority of the traffic sent over a FlapConnection is on channel 2 in the form of SNAC commands. Almost all of AIM's functionality is based on SNAC commands.

I don't know what SNAC stands for.

## SNAC families ##

SNAC commands are organized into "families" of commands. Generally, commands in the same family serve a similar purpose or correspond to the same area of the protocol.

The families used by AIM 5.9 are:

| '''Family''' | '''Purpose''' |
|:-------------|:--------------|
| 0x0001 | Basic connection management / miscellaneous |
| 0x0002 | UserInfo |
| 0x0003 | BuddyStatus notifications |
| 0x0004 | InstantMessages |
| 0x0006 | InviteaFriend |
| 0x0007 | AccountAdmin |
| 0x0008 | PopupMessages |
| 0x000d | ChatRoomSetup |
| 0x000e | Chat Room Activity |
| 0x000f | UserSearch |
| 0x0010 | BuddyIconServer |
| 0x0013 | ServerStoredInfo (buddy list, etc.) |
| 0x0015 | ICQ-specific commands |
| 0x0017 | InitialAuthentication |
| 0x0018 | Email |

A SNAC family may also be called a "service," although the terms mean slightly different things.

The OSCAR protocol provides a means of redirecting SNAC commands in certain families to other OSCAR servers which support those families. For example, the main connection (also called the BOS connection) generally supports families 0x0001 through 0x0008 (excluding 0x0005, which is the no-longer-used advertisements family, and 0x0007) and 0x0013, but not 0x000d, 0x000e, 0x000f, or 0x0010. These "SNAC services" are provided by separate OSCAR connections. (In general, all OSCAR servers except the InitialAuthentication server support family 0x0001 and one or more other families. The InitialAuthentication server implicitly only supports 0x0017.)

Old SNAC families that are '''''no longer used''''' are:

| Family | Old purpose | Reason no longer used |
|:-------|:------------|:----------------------|
| 0x0005 | Advertisements | Ads are now retrieved via HTTP |
| 0x0009 | Privacy settings | Privacy information is now stored using server-stored information (family 0x0013) |
| 0x000a | User search | UserSearch is now done with family 0x000f |
| 0x000b | Client statistics | Only used in older clients and in ICQ (though a SNAC in this family is still sent after signing on, it can be ignored) |
| 0x000c | Unknown | Only used in older clients |

## Structure ##

A SNAC command has the following structure:

[[Include(/Format)]]

No length is provided in the SNAC command structure like in other structures like TLV's and FLAP packets. This is because each SNAC command is sent as the data block of a FLAP packet, whose length is specified and thus already known.

The `family` and `subtype` values identify which SNAC command is being sent. That is, each SNAC command has a unique combination of `family` and `subtype`.

The format of the data block (`data`) varies between individual SNAC commands.

### SNAC flags ###

In general, the SNAC flags `flags` are 0.

In some cases, the server will send a SNAC packet whose `flags` has the 0x8000 bit set. When the 0x8000 bit is set (see DataRepresentation for details on handling bit flags), the SNAC data has been prepended with a TlvChain. The format of the SNAC data is:

  * UnsignedShort: `len`
  * Data: `data`
    * TlvChain
      * TlvBlock type 0x0001
        * UnsignedShort: `familyVersion`
  * Data: `originalSnacData`

There are other flags associated with SNAC's as well though. I will provide a simple table to hopefully fill you in on them. They should be self explanitory. More Replies Follow is used in the buddylist if its a large buddylist.

| Flag | Purpose |
|:-----|:--------|
| 0x8000 | Optional TLV Present |
| 0x0001 | More Replies Follow |
| 0x0002 | Client SNAC |

`len` is the length of the `data` block that contains the TLV chain. `originalSnacData` is the actual SNAC data.

`familyVersion` is the version number of the SNAC family of which the given SNAC packet is a member. (This is the version number you specified while LoggingIn.) I don't know why this is sent.

## SNAC request ID's ##

The SNAC system provides a means of automatically matching up responses to the client's SNAC commands. Many SNAC commands in the OSCAR protocol have logical "responses."

When requesting another user's user profile, you expect a response that contains that user's profile (or an error message if that user is not online). When you send an IM, you receive an acknowledgement packet in response, indicating that the message was sent (or, again, an error message). There are many other scenarios where responses are expected.

A problem with such systems, however, is knowing how to match up responses to their original requests. For example, if some sort of plugin for an AIM client is secretly sending an IM to a bot to retrieve weather information (bear with me please), and at the same time, the user using that client sends a message to his friend, and one acknowledgement packet is received and one error message is received, there is no way to tell which message was sent successfully and which one failed.

While there are many ways around problems like that, the one chosen by the OSCAR developers was a request ID system. Every SNAC packet contains a 32-bit request ID (an UnsignedInt). When the client sends a SNAC packet, all direct responses sent back to the client will have that same request ID as the original packet the client sent. It is thus the client's responsibility to give each outgoing SNAC packet a request ID unique to the other packets it has sent.

Request ID's sent by the OSCAR client must lie between 0 and 2,147,483,647 (inclusive). (In other words, the 0x80000000 bit cannot be set.) That is the only formal restriction on the values of request ID's. Request ID's do not need to be sequential, unique, or anything else. If a client wanted to, it could send every SNAC packet with a request ID of 0.

The request ID for packets sent by the OSCAR server which are not in response to a specific client request have request ID's ranging from 2,147,483,648 to 4,294,967,295 (inclusive). (In other words, the 0x80000000 bit is set.)

In this documentation project, SnacResponse is used to indicate when a server response will have the same request ID as a previous request.