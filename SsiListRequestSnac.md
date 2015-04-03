Clients send this SNAC to the server to check if the current SSI buddy list stored on the client machine is up to date. If the client side SSI information is not up to date, the entire buddy list is sent back via one or more SsiDataSnac packets.

[[Include(/Format)]]

The `lastModified` paramater is a timestamp of the last SSI update in standard `time_t` format. `numEntries` is the number of entries in the local SSI buddy list. Sending incorrect data for either of these parameters is a good way to get the entire buddy list from teh server. (See AIM client version 5.5.3501 - the number of SSI entries is always incorrect).