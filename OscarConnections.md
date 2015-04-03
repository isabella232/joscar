## Connection Hierarchy ##

A typical connection to AOL's AIM servers, an AIM session, consists of several actual TCP connections. A typical set of connections looks like the following tree. In the tree, a parent node's "children" are the connections to which the parent redirected the client.

  * Authorization connection
    * BasicOnlineService (BOS) connection
      * BuddyIconServer connection
      * UserSearch Server connection
      * ChatRoomSetup Server connection
        * ChatRoomServer connection
        * ChatRoomServer connection
        * ChatRoomServer connection...

Each connection directly below the BOS connection is called a "service connection."

### OSCAR connections ###

Each connection to AIM's OSCAR servers (aside from the AolProxyServer) is a FlapConnection.

### Basic Online Services Redirect ###

Upon successful authentication, contained in the Logon Reply is the IP address of the BOS server assigned your session has been assigned to, and a 256 byte cookie to allow the server to authenticate you. As shown in the InitialAuthentication page:

[[Include(AuthResponseSnac/Format/Success)]]

### Service Redirects ###

As shown in the connection hierarchy, the BOS Server directs the client to connect to additional servers that provide the functionality for parts of the AIM service. The BOS Server redirects the client using a family 0x0001 type 0x0005 SNAC, as shown below.

[[Include(RedirectSnac/Format)]]

The `serviceId` field describes the type of server you are being redirected to:

| '''`serviceId`''' | '''type''' | '''example ip''' |
|:------------------|:-----------|:-----------------|
| 13 | ChatRoomSetup Server | 205.188.176.69 |
| 14 | ChatRoom Server | 64.12.201.35 |
| 15 | UserSearch Server | 205.188.4.128 |
| 24 | BuddyIconServer | 205.188.248.173 |

''(these are the only'' `serviceIds` ''that I have encountered, I will update this if I encounter more)''

I'm pretty sure that the protocol allows for any SNAC family to be redirected. So, the serviceId field is more like snacFamilyId and it has potentially any value, because the value is just a SNAC family. However, you're probably right, I think only those three are redirected by AOL's servers.