The receive typing state SNAC is sent by the OSCAR server to indicate a buddy's current typing state. The format of this packet is:

[[Include(/Format)]]

> /!\ Note: This packet has the same SNAC family code and type code as the SendTypingStateSnac. The only logical difference between this command and the Send version is that one is sent by the OSCAR server and the other is sent by the OSCAR client.

`nulls` is normally a set of 8 null (0x00) bytes. As of this writing, this value's significance is unknown.

`code` is a value that appears to always be 1. As of this writing, this value's significance is unknown.

`screenname` is the screenname of the user whose the typing state this command contains.

`state` is a code for the current typing state. Valid values are as follows:

| State | Description |
|:------|:------------|
| 0 | Not typing, or erased what was typed, or typed message was sent |
| 1 | Typed something, then stopped typing |
| 2 | Currently typing a message |

Some AIM clients send a typing state of 0 right before or right after sending a message. Most clients send the typing state 1 ("typed something") after the user doesn't type anything for a few seconds.