The client-is-ready SNAC is sent by the OSCAR client as the final step of LoggingIn. The format of this packet is:

[[Include(/Format)]]

The SNAC contains a series of SnacFamilyVersionsBlock``s, one for each SNAC family supported.

Since your client does not use the AIM modules ("tools"), it should probably emulate the values sent by the official AIM clients. See ClientReadySnac for details. As of AIM 5.5.3415 beta, the SNAC family versions and tool versions sent are as follows:

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