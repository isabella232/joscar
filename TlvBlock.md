A TLV is a data structure containing only a block of data and a "data type" code. (The name comes from '''T'''ype, '''L'''ength, '''V'''alue.) The structure looks like this:

[[Include(/Format)]]

Unfortunately, data type codes (`type`) do not identify the "type" of the data enclosed in a traditional sense. Instead, TLV types are only relevant for the command or data structure in which they are present. For example, a TLV of type 0x0001 contains a US-ASCII-encoded screenname in the authorization SNAC command, but a TLV of type 0x0001 in the security information part of one's UserInfo contains the user's X.509v3 certificate.

`length` contains the length of the `data` block. (So the length of a TLV is `4+length`.)