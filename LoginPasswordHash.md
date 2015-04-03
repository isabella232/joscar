When logging into AIM, the user's password is never actually sent to the server. Without any sort of protection (such as SSL), doing so would be unsafe, as it would allow someone to easily discover a user's password.

## Old password hashing ##

Before AIM 5.2, the password was encrypted by taking an Md5Hash of the authentication key provided by the server, the password (encoded as US-ASCII), and the string "AOL Instant Messenger (SM)", also as US-ASCII. This sixteen-byte MD5 hashblock was then sent as the encrypted password block. To encode this way in Java, you could use code like the following:

{{{#!code java
// we assume this is defined
String pass; // the user's password
byte[.md](.md) key; // the authentication key data provided by the server

byte[.md](.md) passBytes;
byte[.md](.md) aimsmBytes;
try {
> passBytes = pass.getBytes("US-ASCII");
> aimsmBytes = "AOL Instant Messenger (SM)".getBytes("US-ASCII");
} catch (UnsupportedEncodingException impossible) {
> // every VM is required to support US-ASCII
}

MessageDigest md5;
try {
> md5 = MessageDigest.getInstance("MD5");
} catch (NoSuchAlgorithmException impossible) {
> // the default provider always supports MD5
}

md5.update(key);
md5.update(passBytes);
md5.update(aimsmBytes);

byte[.md](.md) encryptedPass = md5.digest();}}}

At the end of that code block, {{{encryptedPass}}} contains the encrypted password data suitable for sending in an authorization request.

== New password hashing ==

As of AIM 5.2, a new password hash algorithm is used. The algorithm is similar to the original; the only difference is that instead of using the password data in the Md5Hash, an ''MD5 hash of the password data'' is used. This algorithm can be implemented in Java with code like the following:


{{{#!code java
// we assume this is defined
String pass; // the user's password
byte[] key; // the authentication key data provided by the server

byte[] passBytes;
byte[] aimsmBytes;
try {
    passBytes = pass.getBytes("US-ASCII");
    aimsmBytes = "AOL Instant Messenger (SM)".getBytes("US-ASCII");
} catch (UnsupportedEncodingException impossible) {
    // every VM is required to support US-ASCII
}

MessageDigest md5a;
MessageDigest md5b;
try {
    md5a = MessageDigest.getInstance("MD5");
    md5b = MessageDigest.getInstance("MD5");
} catch (NoSuchAlgorithmException impossible) {
    // the default provider always supports MD5
}

// get an MD5 hash of the password itself
passBytes = md5a.digest(passBytes);

// this is a new MD5 hash
md5b.update(key);
md5b.update(passBytes);
md5b.update(aimsmBytes);

byte[] encryptedPass = md5b.digest();
}}}

After this code block, {{{encryptedPass}}} contains the AIM 5.2 password hash. While two message digest objects were used in the above example for clarity, a single digest object could be used and reset after the password's MD5 hash is computed.

When using this new hash algorithm, an extra 0x4c TLV must be sent with the encrypted data block in the authorization request to indicate that the new algorithm was used.
Hi this is Xhacker here..... sup? YEah!
```