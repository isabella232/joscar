The warn buddy SNAC is sent by the OSCAR client to increase a buddy's warning level. The format of this packet is:

[[Include(/Format)]]

`anonymousCode` is a code indicating whether the warning should be anonymous. Possible values are as follows:

| Code | Meaning |
|:-----|:--------|
| 0 | Warning is not anonymous |
| 1 | Warning is anonymous |

When you warn someone with an anonymous code of 0, the server tells the him or her that it was you who warned them. When you warn someone anonymously, the warning level increase is smaller (less severe), but the user is not told who warned them.

`screenname` is the screenname of the user to be warned.