The SSI data modified check is sent by the OSCAR client to check if the current SSI buddy list stored on the client machine is up to date. If the client-side SSI information is not up to date, the entire buddy list is sent back via one or more SsiDataSnac packets. If the information is up to date, an SsiUnchangedSnac is returned.

[[Include(/Format)]]

The `lastModified` parameter is a timestamp of the last SSI update that the client saw.

`numItems` is the number of items the client has in its copy of the SSI; that is, the number of items that were in the list when the client last saw it.

Sending incorrect values for either of these parameters will cause the server to send the entire list back in one or more SsiDataSnac```s (as SnacResponse```s). (In AOL's official AIM client version 5.5.3501, the number of SSI entries is always incorrect, so it always receives the entire buddy list.) If the values sent in this command match the server's copy of the SSI, the server will send an SsiUnchangedSnac (as a SnacResponse).