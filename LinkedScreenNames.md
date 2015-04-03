"Linked screen names" was introduced in AIM 5.5 beta. This feature allows you to set up multiple screen names that can be signed on automatically after signing onto a single one of the screen names.

This will be documented more thoroughly later, but here is a quick description:

The "Manage Linked Screen Names" website, http://www.aim.com/redirects/inclient/linkingsn.adp, allows the user to select a set of screen names to be linked after entering a password for each one. It appears that the website automatically, without client interaction, modifies that screenname's ServerStoredInfo, setting the linked screenname entries to their appropriate values. Changes do not seem to take effect in the Windows client until you log out and then log back in.

Adding the screenname Bobby1234 to the Linked Screen Names list of Jimmy6789 modifies the SSI of both screennames. In other words, linking screenname A to screenname B appears to be exactly the same as linking screenname B to screenname A.

Upon logging in, the AIM client looks at its linked screenname items, and for each one, it sends a service request SNAC for family 0x0001, the basic connection (BOS) family, with a new TLV that contains the screenname, as well as some sort of cookie.

The server responds with a normal service response, and the client opens that connection. The connection is just like any other BOS connection except that it can set its ICQ status to "invisible" using an SetExtraInfoSnac. When this flag is set, the AIM server acts as if that screenname signed off. When the status is set back to visible, it appears that the client has just signed on.