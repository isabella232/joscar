An unsigned short is a two-byte (16-bit) unsigned data type that contains an integer from 0 to 65,535 (inclusive). Unsigned shorts are sent in big-endian (network byte order) format over the OSCAR protocol.

An unsigned short cannot be stored in Java's `short` type because `short` is signed.

To read an unsigned short from a byte array into Java's `int` type, you can use code like the following:

```
// we assume this is defined
byte[] data;

int ushortValue = (data[0] & 0xff) << 8) | (data[1] & 0xff);
```

To write an unsigned short from Java's `int` type to an output stream, you can use code like the following:

```
// we assume these are defined
OutputStream out;
int number;

out.write((byte) ((number >> 8) & 0xff));
out.write((byte) (number & 0xff));
```