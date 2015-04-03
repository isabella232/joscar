A miniature chat room information block contains brief information about a chat room. This structure is sent in chat room invitations and chat room service requests.

A miniature chat room information block has the following structure:

  * UnsignedShort: `exchange`
  * UnsignedByte: `cookieLen`
  * AsciiString: `cookie`
  * UnsignedShort: `instance`

`exchange` is the exchange number where the chat room resides.

`cookieLen` is the length of the `cookie` block, in bytes. `cookie` is a string that serves both as the chat room cookie (for a chat room service request) and as information about the room itself. A chat room cookie is generally of the form `!aol://2719:11-4-room%20name`. The room name is URL-encoded.

To extract the room name in Java, you could use the following method:

```
/**
 * A regular expression that matches the "cookie" or "URL" of a chat room.
 */
private static final Pattern roomNameRE
        = Pattern.compile("!aol://\\d+:\\d+-\\d+-(.*)");

/**
 * Returns the name of the chat room described by the given "cookie" or
 * "chat room URL." For example, with the input 
 * <code>"!aol://2719:11-4-room%20name"</code>, this method will return
 * <code>"room name"</code>.
 *
 * @param cookie a chat room "cookie"
 * @return the name of the chat room described by the cookie
 */
public static final String getRoomNameFromCookie(String cookie) {
    Matcher m = roomNameRE.matcher(cookie);
    if (!m.matches()) return null;

    String encodedName = m.group(1);

    String name = null;
    try {
        name = URLDecoder.decode(encodedName, "us-ascii");
    } catch (UnsupportedEncodingException impossible) {
        // every VM is required to support US-ASCII
    }

    return name;
}
```