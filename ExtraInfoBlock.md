# Extra Info Blocks #

An "extra info block" is a structure containing a type, a set of bit flags, and a block of data whose length is 0-255 bytes.

Extra info blocks are used in iChat availability messages, AimExpressions, the new BuddyIconServer, and AimSecureIm.

## Structure ##
The structure is as follows:

  * UnsignedShort: `type`
  * UnsignedByte: `flags`
  * UnsignedByte: `len`
  * Data: `data`

`len` represents the length of the `data` block. (Thus, the length of an entire extra info block is `4 + len`.)

`flags` contains a set of bit flags.

## Type ##

Known values for `type` are:

| `type` | description |
|:-------|:------------|
| 0x0001 | Buddy icon information |
| 0x0002 | iChat availability message |
| 0x0080 | AIM Expression information |
| 0x0082 | AIM Expression information |
| 0x0402 | Mysterious AimSecureIm MD5 hash |
| 0x0403 | Mysterious AimSecureIm MD5 hash |

## Bit flags ##

The meaning of the bit flags differs between each extra info block type.

### Bit flags for buddy icon blocks ###

The buddy icon extra info block (type 0x0001) is used in both setting one's buddy icon (as a client) and in being told what your (and other users') buddy icons are.

#### Setting buddy icons ####

When setting your buddy icon, the flag 0x01 should be set and the data should be an MD5 hash of the buddy icon.

When clearing (removing) your buddy icon, no flags should be set and the data should be `0201d20472`.

For more information on setting buddy icons, see the BuddyIconServer section.

#### Buddy icon confirmation ####

After setting your buddy icon, and upon login, you will be sent a list of your extra info blocks.

If your type 0x0001 block has the 0x40 bit flag set, you should upload your buddy icon to the BuddyIconServer.

If your type 0x0001 block has the 0x80 bit flag set, the server has a cached copy of your buddy icon and you do not need to upload it.

Note that the 0x0001 flag will be on if you have an icon set.

#### Other buddies' buddy icons ####

This section deals with extra info blocks in a user's UserInfo.

When a buddy has a buddy icon, the flag 0x01 will be set and the data will be an MD5 hash of his buddy icon.

When a buddy has no buddy icon, either he will not have an 0x0001 extra info block or no flags in the block will be set and the data will be the SpecialHash block.

### Bit flags for iChat availability messages ###

iChat availability message blocks have the 0x04 bit flag set.

### Bit flags for AIM Expressions blocks ###

No bit flags are set for AIM Expressions blocks.

Sup? I hate fags like u!!