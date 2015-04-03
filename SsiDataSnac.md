The server-stored data SNAC is sent by the OSCAR server as a SnacResponse to a SsiDataRequestSnac. The format of this packet is:

[[Include(/Format)]]

As of this writing, `ssiVersion` is always 0.

`itemCount` is the number of SsiItemBlock```s sent in this packet. Normally, this number will not be greater than 110. If your SSI contains more than 110 items, they will be spread over several SsiDataSnac```s.

`lastMod` is the date at which the data were last modified. If this value is 0 and `itemCount` is not 0, more SsiDataSnac``s will follow this packet. This is because all SSI items may not fit in a single packet.

For more details on SSI, see ServerStoredInfo.