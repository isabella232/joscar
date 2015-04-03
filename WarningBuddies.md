Warning ("eviling") is the AIM way of telling a buddy that you don't like what they're doing. With higher warning levels come lower rate limits, so this is an effective way of limiting someone who is spamming you.

### Warn buddy command ###
From WarnBuddySnac:
[[Include(WarnBuddySnac)]]

### Warn acknowledgment ###
The Warn Ack command is sent by the OSCAR server as a SnacResponse to the WarnBuddySnac. The format of this packet is dependent on the success of the warn operation.

#### Successful warning ####

  * SnacCommand family 0x04, 0x09
    * UnsignedShort: `amountWarned`
    * UnsignedShort: `newLevel`

`amountWarned` is the amount the user warned the buddy in that warning. If the buddy were at 30% and
the user warned them to 40%, this would be 10%; note, as with other warning packets, these numbers are the
warning level times 10. (30% = 300)

`newLevel` is the buddy's new warning level, once again, their level times 10.

#### Failed warning ####

  * SnacCommand family 0x04, 0x09
    * UnsignedShort: `unknown` (usually 0x000d)
    * TlvBlock type 0x0008
      * UnsignedShort: `unknown`

The meanings of the data portions are unknown.

### Warned command ###
From WarnedSnac:
[[Include(WarnedSnac)]]