User class masks are used in OSCAR to describe "classes" of users. Class masks are used in ServerStoredInfo and in UserInfoBlock``s.

A class mask is represented as an UnsignedInt (SirG3: it appears to be an UnsignedShort to me, Aug 5, 2005). It consists of a set of bit flags:

| Bit Flag | Description |
|:---------|:------------|
| 0x0020 | User is away |
| 0x0001 | User has not responded to signup confirmation email |
| 0x0002 | User is an AOL administrator |
| 0x0010 | User is not an AOL member; is using AIM |
| 0x0080 | User is on a mobile device |
| 0x0400 | User is an Active``Buddy robot |