MD5 hashing is a common way to relatively uniquely identify a block of data. MD5 hashes are used for several different things within OSCAR. An MD5 hash block is 16 bytes long, no matter how long the data block being hashed is.

Producing an MD5 hash of a block of data in Java is simple:

{{{#!code java
// we assume this is defined
byte[.md](.md) data; // the data to be hashed

MessageDigest md5;
try {
> md5 = MessageDigest.getInstance("MD5");
} catch (NoSuchAlgorithmException impossible) {
> // the default provider always supports MD5
}

// compute the MD5 hash
byte[.md](.md) hash = md5a.digest(passBytes);}}}

An MD5 hash cannot be reversed; the data being hashed cannot be retrieved from an MD5 hash. If this were true, then any block of data of any size could be stored in 16 bytes, and that is impossible.

Instead, if you want to see if an MD5 hash matches a set of data, you must compute the MD5 hash of the data, and then compare the two MD5 hashes. There are 34 septtrigintillion possible MD5 hashes, so if the hashes match, it is likely that the two blocks of data match.
```