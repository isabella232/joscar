The ICBM parameter information SNAC is sent by the OSCAR server as a SnacResponse to an IcbmParamRequestSnac. The client normally responds to this packet with a SetParamInfoSnac. The format of this packet is:

[[Include(/Format)]]

`paramInfo` will contain the client's current ICBM parameter information. Your ICBM parameter information is set to the default each time you connect, and the defaults are rather restrictive. As of this writing (Oct. 11, 2003), the defaults sent by the official AIM server are as follows:

| Field | Default value |
|:------|:--------------|
| `maxChannel` | 2 |
| `flags` | 0x00000002 | 0x00000001 |
| `maxMsgLen` | 512 bytes |
| `maxSenderWarning` | 99.9% |
| `maxReceiverWarning` | 99.9% |
| `minMsgInterval` | 1000 ms |

For details on ICBM parameter information, see InstantMessages.

Your client will most likely want to change its parameter information to something less restrictive. For details, see LoggingIn.