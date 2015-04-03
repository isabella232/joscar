A key request SNAC is sent by a OSCAR client to request an authentication key to use in encrypting the user's password during InitialAuthentication. Normally, the OSCAR server will respond to this packet with a KeyResponseSnac. The format of this packet is as follows:

[[Include(/Format)]]

`screenname` should be the user's screenname. As of this writing, I do not know what the 0x004b and 0x005a TLV's do; AIM 5.2 sends them, so you should too.