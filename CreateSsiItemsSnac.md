The create SSI items SNAC is sent by the OSCAR client to add items to the user's server-stored information. The server normally responds to this packet with a SsiAckSnac. The format of this packet is:

[[Include(/Format)]]

The `itemN` items are the items being created. The combination of group ID and buddy ID of each item in this list must be different from every item currently in your SSI.

For details, see ServerStoredInfo.