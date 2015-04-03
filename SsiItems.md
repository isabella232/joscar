# SSI Items #

SSI items are stored in a miniature hierarchy. The hierarchy for a single user's SSI might look like this:

  * Root group (gid=0, id=0)
    * Group "Buddies" (gid=12, id=0)
      * Buddy "joustacular" (gid=12, id=2)
      * Buddy "otherbuddy" (gid=12, id=401)
    * Group "Family" (gid=401, id=0)
      * Buddy "someone" (gid=401, id=2)
    * Block item for "enemy84" (gid=0, id=12)
    * Block item for "notfriend" (gid=0, id=20)
    * Allow item for "superfriend" (gid=0, id=108)
    * Visibility settings item (gid=0, id=14)
    * Privacy settings item (gid=0, id=100)
    * Buddy icon hash "1" (gid=0, id=72)
    * Buddy icon hash "2" (gid=0, id=49)

Two items cannot have the same group ID (gid) and item ID.

SSI Items Table of Contents:
[[TableOfContents](TableOfContents.md)]

## Item Format ##

SSI items share a common binary format, regardless of the item type:

[[Include(SsiItemBlock/Format)]]

`name` is the name of the item. It may be an empty string for item types which do not have names.

`groupid` is always 0 for top-level entries such as the "master group," visibility information, linked screen name information, buddy icon information, and allow/block information. In general, it is always 0 for any item which is not a Buddy item.

`itemid` is the item identification number, and must only be unique within its parent group. As stated above, in some cases, two items may share the same group ID and item ID, but it is not allowed for all item types and should be avoided.

`data` contains information specific to the type of SSI entry, and is normally a TlvChain.

## Item Types ##

Below is a table of the SSI item types and what kind of data they contain.

| `type` | Description | Maximum items of that type allowed at once|
|:-------|:------------|:------------------------------------------|
| 0x0000 | A buddy appearing on the user's buddy list | 400 |
| 0x0001 | A group of buddies appearing on the user's buddy list | 61 |
| 0x0002 | An entry in the user's Allow list | 200 |
| 0x0003 | An entry in the user's Deny list (a blocked user) | 200 |
| 0x0004 | The user's permit/deny settings | 1 |
| 0x0005 | The user's presence settings | 1 |
| 0x0014 | Buddy icon information | 15 |
| 0x0017 | List of the user's linked screen names | 1 |
| 0x0018 | Linked screen name | 10 |

**Maximum item values are from January 2004 and are likely to be different in the future. AOL continues to increase the maximum number of allowed buddies.**

### Buddy Items ###
A SSI buddy item has a `type` of 0x0000. Stored in a buddy item are properties of a single buddy, such as his or her screenname, his or her Buddy Comment, and the ID of the group the buddy is in.

`name` is the buddy's screenname. `groupid` is the ID of the group to which the buddy belongs. `itemid` is the buddy's item ID, as described above.

The format of `data` is as follows:

  * TlvChain
    * TlvBlock type 0x13c
      * AsciiString: `comment`
    * TlvBlock type 0x13d
      * UnsignedByte: `actionMask`
      * UnsignedByte: `whenMask`
    * TlvBlock type 0x13e
      * AsciiString: `alertFile`
    * TlvBlock type 0x131
      * AsciiString: `alias`
> /!\ All of these TlvBlock``s may or may not be present in a given buddy item. They are all optional.

`comment` is the user's "buddy comment." As of this writing, the official AIM clients limit this value to 84 ASCII characters.

`actionMask` is a set of bit flags (see DataRepresentation for details on bit flags) describing what should happen when a buddy alert for this buddy is activated. The possible flags are:

| Bit Flag | Action upon alert |
|:---------|:------------------|
| 0x01 | Pop up dialog box |
| 0x02 | Play sound specified in `alertFile` (see below) |

`whenMask` is a set of bit flags describing when alerts for this buddy should be activated. The possible flags are:

| Bit Flag | When to activate alert |
|:---------|:-----------------------|
| 0x01 | When the buddy signs on |
| 0x02 | When the buddy comes back from being idle |
| 0x04 | When the buddy comes back from being away |

`alertFile` is the name of the sound file to play if this buddy has a sound alert set in `actionMask`. This will be a string like "newalert" or "somesound", which correspond to the sound files "newalert.wav" and "somesound.wav".

`alias` is used by some clients including Gaim and ICQ to store an "alias" for the buddy. In those clients, this alias shows up on the user's buddy list instead of the buddy's actual screenname.

### Group Items ###

A Group item has a `type` of 0x0001. A Group item contains information about a single group of buddies on the user's buddy list.

`name` is the name of the group.

`groupid` is the ID of this group. Buddy items in this group have this `groupid`. The group with a `groupid` of 0 is called the "master group" (see below for more information on the master group).

`itemid` is 0 for all group items.

The format of `data` is as follows:

  * TlvChain
    * TlvBlock type 0xc8
      * UnsignedShort: `itemid1`
      * UnsignedShort: `itemid2`
      * UnsignedShort: `itemid3`...

For the master group, the `itemidN` values are the `groupid`s of the Group items in the user's buddy list. The order of the group ID's listed is the order of the associated groups displayed on the user's buddy list in AOL's official AIM clients. If a group's ID is present twice or more in the list, AOL's AIM clients display the group in the position of the ''last'' instance of that group ID.

For normal buddy groups, the `itemidN` values are the `itemid`s of the Buddy items in this group. The order of the buddy ID's listed is the order of the associated buddies displayed on the user's buddy list in this group. If a buddy's ID is present twice or more in the list, AOL's AIM clients display the buddy in the position of the ''last'' instance of that buddy ID.

### Allow Items ###

Allow items have a `type` of 0x0002. An Allow item describes a single screenname on the user's Allow list.

`name` is the allowed user's screenname.

All Allow items have a `groupid` of 0.

Normally, `data` is empty.

### Block Items (Deny items) ###

Block items have a `type` of 0x0002. A Block item describes a single blocked screenname on the user's Block list.

`name` is the blocked user's screenname.

All Block items have a `groupid` of 0.

Normally, `data` is empty.

### Privacy Settings Items ###

Privacy settings items have a `type` of 0x0004. A privacy item contains information about who is allowed and who is blocked.

Normally, `name` is empty.

Privacy items have a `groupid` of 0.

The format of `data` is as follows:

  * TlvChain
    * TlvBlock type 0xca
      * UnsignedByte: `mode`
    * TlvBlock type 0xcb
      * UnsignedInt: `classMask`
    * TlvBlock type 0xcc
      * UnsignedInt: `visibleMask`
> /!\ All of these TlvBlock``s may or may not be present in a given privacy settings item. They are all optional.

`mode` is a number describing the user's "privacy mode." Possible values are as follows:

| Privacy Mode | Meaning |
|:-------------|:--------|
| 1 | Allow all users to contact me |
| 2 | Block all users |
| 3 | Allow only users on Allow list |
| 4 | Allow all users not on Block list |
| 5 | Allow only users on my buddy list |

`classMask` is a set of bit flags describing which classes of users should be allowed. A value of 0xFFFFFFFF allows all users. For details on class masks, see ClassMask.

`visibleMask` is a set of bit flags describing what is visible to other users. The possible flags and their meanings are as follows:

| Bit Flag | "Allow other users to see..." |
|:---------|:------------------------------|
| 0x00000002 | ...that I am using a mobile device |

### Visibility Settings Items ###

Visibility Settings items have a `type` of 0x0005. A visibility settings item contains information

Normally, `name` is empty.

Visibility settings items have a `groupid` of 0.

The format of `data` is as follows:

  * TlvChain
    * TlvBlock type 0xc9
      * UnsignedInt: `visMask`
    * TlvBlock type 0xdc
      * ''(format unknown as of this writing)''
> /!\ All of these TlvBlock``s may or may not be present in a given visibility item. They are all optional.

`visMask` is a set of bit flags indicating the following:

| Bit Flag | "Allow other users to see..." |
|:---------|:------------------------------|
| 0x00000400 | ...how long I've been idle |
| 0x00400000 | ...that I am typing a response |

### Buddy Icon Items ###

A Buddy Icon item has a `type` of 0x0014. A Buddy Icon item contains information about a single buddy icon file.

`name` is normally a single ASCII digit, like "1".

Buddy icon items have a `groupid` of 0.

The format of `data` is as follows:

  * TlvChain
    * TlvBlock type 0xd5
      * ExtraInfoBlock type 0x0001: `iconInfo`
    * TlvBlock type 0x131 ''(empty)''
> /!\ All of these TlvBlock``s may or may not be present in a given icon item. They are all optional.

`iconInfo` is an extra info block with a type of 0x0001. If the 0x0001 extra info flag is set, the data within is an MD5 hash of a buddy icon. If that flag is not set, the data within is the SpecialHash, indicating "no buddy icon."

### SSI Linked Screen Names List ###

If `type` is equal to 0x0017, then the SSI record stores a list of the linked screen names.

For this SSI type, `groupid` will always be 0x0000, `itemid` is a locally unique identifier, `name` is null, and `data` is a TlvChain with one TlvBlock of type 0x00C8 containing a list of the `itemid`s of the linked screen names.

### SSI Linked Screen Name ###
If `type` is equal to 0x0018, then the SSI record stores a linked screen name.

For this SSI type, `groupid` will always be 0x0000, `itemid` is a locally unique identifier, `name` is the name of the linked screen name, and `data` is null.