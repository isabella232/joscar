# Data representation in the OSCAR protocol #

Data are represented in many ways throughout the protocol. Certain formats are common among many SNAC commands and OSCAR data structures.

## Representation of numbers ##

Numbers in the OSCAR protocol are almost exclusively represented as big-endian (network byte order) unsigned integers. The most common representations are UnsignedInt, UnsignedShort, and UnsignedByte.

## Representation of dates ##

Dates and times are represented in OSCAR as UnixDate``s.

## Representation of text ##

All text sent over the OSCAR protocol is either accompanied with a charset or is implicitly encoded as US-ASCII (referred to here as an AsciiString). Methods of identifying the charset encoding of a given string vary and are explained in their respective sections of this documentation project.

## Bit flags ##

Several parts of OSCAR use bit flags to identify certain boolean properties of commands or data structures. A bit flag is a bit in a series of bits. 0x40, for example, represents bit flag because it contains only one "on" bit: 01000000. 0x51, for example, does not represent a bit flag because it has many bits on: 01010001. 0x51 could be, however, a combination of three bit flags: 0x40, 0x10, and 0x01.

To see if the bit flag 0x40 is on in the value `bitFlags` in Java, one could use code such as the following:

{{{#!code java
// we assume this is defined
int bitFlags; // could also be long, short, or byte

if ((bitFlags & 0x40) != 0) {
> System.out.println("Bit 0x40 is on!");
}}}}

To set the bit 0x40 on in the value {{{bitFlags}}} in Java, you could use code such as the following:

{{{#!code java
// we assume this is defined
int bitFlags; // could also be long, short, or byte

bitFlags = bitFlags | 0x40;
}}}

To set the bit 0x40 '''''off''''' in the value {{{bitFlags}}} in Java, you could use code such as the following:

{{{#!code java
// we assume this is defined
int bitFlags; // could also be long, short, or byte

bitFlags = bitFlags & ~0x40;
}}}

```