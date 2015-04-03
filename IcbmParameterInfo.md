ICBM parameter information defines limitations and capabilities involved in InstantMessaging and ClientToClientCommunication.

The structure of an ICBM parameter information block is as follows:

  * UnsignedShort: `maxChannel`
  * UnsignedInt: `flags`
  * UnsignedShort: `maxMsgLen`
  * UnsignedShort: `maxSenderWarning`
  * UnsignedShort: `maxReceiverWarning`
  * UnsignedInt: `minMsgInterval`

It should be noted that maxSenderWarning and maxReceiverWarning are percentages. Values range from 0-1000 (0% - 100%).
