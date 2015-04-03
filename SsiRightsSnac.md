The SSI rights SNAC is sent by the OSCAR server as a SnacResponse to a SsiRightsRequestSnac. The format of this packet is:

[[Include(/Format)]]

`maxN` is the maximum number of SSI items of type `N` that can be stored.

As of this writing (Oct. 12, 2003), the maximum number of items of each type allowed on AOL's AIM servers are as follows (the table is split into two tables):

| Type | 0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x5 | 0x6 | 0x7 | 0x8 | 0x9 | 0xa | 0xb | 0xc | 0xd | 0xe | 0xf |
|:-----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|:----|
| Max. | 400 | 61 | 200 | 200 | 1 | 1 | 150 | 12 | 12 | 0 | 50 | 50 | 0 | 0 | 0 | 0 |

| Type | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 |
|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|:-----|
| Max. | 0 | 1 | 0 | 0 | 10 | 1 | 40 | 1 | 10 |

For details, see the SSI rights documentation in LoggingIn.