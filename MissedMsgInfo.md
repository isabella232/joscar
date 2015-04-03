The missed message information block is used to hold information about one or more InterClientBasicMsg``s (ICBM's) that were missed due to limitations specified in IcbmParameterInfo. [other details](insert.md). The format of this data structure is as follows:

[[Include(/Format)]]

`channel` is the ICBM channel on which this message was missed. Valid channel values are described in InterClientBasicMsg.

`senderInfo` is a user info block for the user whose messages were missed.

`count` is one more than the number of messages that were missed. For example, if two messages were missed, this value would be 3. As of this writing, this is not known exactly, but it appears to be what it means. The reasoning behind adding one to the value is unknown as well.

`reason` is a code indicating why the messages were missed. Possible values are below:

| Reason | Description |
|:-------|:------------|
| 1 | The messages were too large |
| 2 | The messages were sent too fast |
| 3 | The sender's warning level was too high |
| 4 | Your warning level is too high |