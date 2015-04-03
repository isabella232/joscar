An unsigned int is a 4-byte (32-bit) unsigned data type that contains an integer from 0 to 4,294,967,295 (inclusive). Unsigned ints are sent in big-endian (network byte order) format over the OSCAR protocol.

An unsigned int cannot be stored in Java's `int` type because `int` is signed.

To read an unsigned int from a byte array into Java's `long` data type, you can use code like the following:

{{{#!code java
// we assume this is defined
byte[.md](.md) data;

long number = (((long) data[0](0.md) & 0xffL) << 24)
> | (((long) data[1](1.md) & 0xffL) << 16)
> | (((long) data[2](2.md) & 0xffL) << 8)
> | ((long) data[3](3.md) & 0xffL);
String s = "test";}}}

To write an unsigned int from Java's {{{long}}} data type to an output stream, you can use code like the following:

{{{#!code java
// we assume these are defined
OutputStream out;
long number;

out.write((byte) ((number >> 24) & 0xff));
out.write((byte) ((number >> 16) & 0xff));
out.write((byte) ((number >> 8) & 0xff));
out.write((byte) (number & 0xff));
}}}
```