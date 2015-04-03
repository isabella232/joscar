Sending basic instant messages in the OSCAR protocol is more complicated than just sending text to a screenname.

Table of contents:
[[TableOfContents](TableOfContents.md)]

## Instant Messages ##

Basic instant messages on the OSCAR protocol are sent via InterClientBasicMsg (ICBM) structures on ICBM channel 1.

### Setting up ICBM's ###

Before sending instant messages on a new OSCAR connection, your client should set its ICBM parameter information, as described in LoggingIn.

### Outgoing IM ICBM Format ###

[[Include(OutgoingICBMSnac)]]

### Incoming IM ICBM Format ###

An incoming IM InterClientBasicMsg's `data` field has the following format:

  * UserInfoBlock: `senderInfo`
  * TlvChain: `tlvs`

`senderInfo` is a user info block for the user who sent you this message.

`tlvs` is a set of TLV's documented below and in the Common TLV's section further below.

The TLV's which must only be present in incoming ICBM's are as follows:

  * TlvBlock type 0x000b ''(empty)'' ''(optional)'': `hasTypingNotification`

If a type 0x000b TLV (`hasTypingNotification`) is present in an incoming IM ICBM, the sender supports TypingNotification packets. This TLV indicates to a client that it should be sending typing notification

### Common IM ICBM TLV's ###

The TLV's which may be present in the `tlvs` field of both outgoing and incoming IM ICBM's are as follows:

  * TlvBlock type 0x0004 ''(empty)'' ''(optional)'': Auto-Response
  * TlvBlock type 0x0008 ''(optional)'': Old Buddy Icon Information
  * TlvBlock type 0x0009 ''(empty)'' ''(optional)'': Old Buddy Icon Request
  * TlvBlock type 0x000d ''(optional)'': AIM Expressions
  * TlvBlock type 0x0002: MessageBlock
The TLV's listed above are described in the following sections.

#### The Auto-Response Flag ####

If a 0x0004 TLV is present in an IM ICBM, the message is an "auto-response." Auto-responses are normally responses that the user did not actually type, like when clients send the user's away message in response to an incoming IM when the user is away.

This TLV does not normally contain any data.

#### Old Buddy Icon Information ####

Before the BuddyIconServer was introduced, a more crude method was used to advertise and collect buddies' Buddy Icons. This method is referred to in this documentation as the "old buddy icon system," and the actual icon file transfer method is documented in OldBuddyIconTransfer.

If an 0x0008 TLV is present in an IM ICBM, the sender has a buddy icon and wants you to have it. The data inside that TLV has the following format:

  * UnsignedInt: `size`
  * UnsignedShort: `checksum`
  * UnixDate: `lastMod`

`size` is the size of the buddy icon file, in bytes.

`checksum` is an OldBuddyIconChecksum of the buddy icon file.

`lastMod` is the last modification date of the buddy icon file.

Normally, if the receiver's copy of the sender's buddy icon information does not match this buddy icon information, the receiver's next IM to the sender should contain an empty 0x0009 TLV, as described in the next section, to request the sender's buddy icon file be sent.

#### The Buddy Icon Request Flag ####

If an IM ICBM contains an 0x0009 TLV, the sender is requesting the receiver's buddy icon. Normally, when a client receives an IM ICBM with this TLV, it sends the buddy icon data in a rendezvous ICBM as described in the OldBuddyIconTransfer documentation.

This TLV normally does not contain any data.

#### The AIM Expressions Information Block ####

A user's AIM Expression information is transmitted in the same clunky way that buddy icon information used to be transmitted (see above for details on old buddy icon transfer).

When a user is using an AIM Expression, the name of the expression is sent in every IM he or she sends out, inside an 0x000d TLV.

The format of the data in this TLV is as follows:

  * ExtraInfoBlock type 0x0080, no flags
    * UnsignedByte: `code1`
    * AsciiString: `aimExpression1`
  * ExtraInfoBlock type 0x0082, no flags
    * UnsignedByte: `code2`
    * AsciiString: `aimExpression2`

As of this writing, `code1` and `code2` both appear to always be 5.

`aimExpression1` and `aimExpression2` contain the name of an AIM Expression, like "the60s". At the time of this writing, it is unknown what the difference between those two blocks are, but when the official AIM clients send them, they both always contain the same AIM expression name.

#### The Instant Message Data ####

Every instant message ICBM contains an 0x0002 TLV, which holds the actual message. Messages in IM ICBM's may be split up into parts, or they may be encrypted. The format of the data in the 0x0002 TLV is as follows:

[[Include(MessageBlock)]]

`Whiscer Caps` is a block of data that specifies internal features of the ICBM, and are defined as follows.
  * Text: 1
  * Talk: 2
  * Video: 3
  * Internal: 4
  * Overhead: 5
  * ICQ Unicode: 6

The TLV that contains `encryptionCode` may or may not be present. If it is present, `encryptionCode` will normally be the value 1, and there will be only one `msgPart`. For more information about encrypted IM, see SecureInstantMessages and, more generally, AimSecureIm.

If no `encryptionCode` is present, the `msgPartN` blocks are EncodedString``s. The actual message sent is the concatenation of all of the message parts. A single message can have any number of message parts.

##### Message Parts #####

Message parts are not used by modern clients, but were used by older clients to support Unicode without doubling the binary message size. (Unicode characters are two bytes; ASCII/ISO-8859 characters are one byte.) If the user typed a 2KB message with a single non-ASCII character, AIM developers felt it was unnecessary to use 4KB just to represent it as Unicode. Message parts allow only a few extra bytes to be used for that one non-ASCII character. In this case, the message parts could look something like:

  * EncodedString type ASCII: 500 bytes
  * EncodedString type UTF16: 2 bytes
  * EncodedString type ASCII: 1500 bytes

This might have been a good idea, but was probably unnecessary, as UTF-8 could have been used and would have saved similar bandwidth. Either way, as stated above, this construct is not used in modern clients; modern clients always send a single message part. For backwards compatibility, however, clients should parse multiple message parts correctly, by simply decoding each part and merging them together into one string.

### Missed Messages ###

If someone sends you an IM (or some other kind of InterClientBasicMsg (ICBM), probably) too quickly, or sends you a message that is too long, according to your IcbmParameterInfo, and you have the appropriate missed-messages flag enabled in your IcbmParameterInfo, you will receive a MissedMsgsSnac. The format of this packet is as follows:

[[Include(MissedMsgsSnac/Format)]]

Each missed message information block contains information about the messages that were missed. For details, see MissedMsgsSnac.

## Typing Notification ##

Typing notification is explained in TypingNotification.

## Warnings ##

Warnings are used in several places in the protocol. In one's IcbmParameterInfo, the client can set the maximum warning level that is allowed for buddies sending you IM's, and vice versa. A buddy's warning level is contained in his or her UserInfoBlock, and a few other places.

If you're unfamiliar with warning levels, you can read more general information about warning levels at [AOL's warnings FAQ](http://www.aol.com/aim/faq/warnings.html).

### Warning a buddy ###

To warn a buddy, you must have received an IM from that buddy less than a certain amount of time ago. I don't know what that amount of time is. To warn a buddy, you send a WarnBuddySnac. For details, see the WarnBuddySnac documentation.

### Being warned ###

When a buddy warns you, the server sends you a WarnedSnac. For details, see the WarnedSnac documentation.

After being warned, your warning level will slowly decrease over time. You will not receive WarnedSnac``s each time your warning level decreases; instead, to track your warning level, you may want to add your own screenname to your buddy list and track buddy updates (as described in BuddyList).