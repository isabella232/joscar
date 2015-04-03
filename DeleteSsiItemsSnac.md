The delete SSI items SNAC is sent by the OSCAR client to remove items from the user's server-stored information. The server normally responds to this packet with a SsiAckSnac. The format of this packet is:

[[Include(/Format)]]

The `itemN` items are the items to be deleted. The items should have the same name, type, parent ID, and group ID as the items you want to delete, but the item data may be empty, to save bandwidth.

For details, see ServerStoredInfo.