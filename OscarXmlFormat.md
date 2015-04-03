This is a page for discussing the OSCAR XML data structure description format.

I think the file format should be independent of Java and just about anything else. XML-style naming conventions should be used (several-word-name instead of severalWordName). I think that binding XML types should be done externally, like a file that contains a table (to be parsed by the code generation code):

| XML type | Java classname |
|:---------|:---------------|
| tlv | Tlv |
| tlv-chain | TlvChain |

A description of a TLV:
{{{#!xml


&lt;tlv&gt;


> 

&lt;ushort attr="type" /&gt;


> 

&lt;ushort id="len" /&gt;


> 

&lt;data bytelen="$len" /&gt;




&lt;/tlv&gt;

}}}

You'd access the TLV type using Tlv.getType(), and the data via Tlv.getData(). This is because the first ushort defines an "attr" - any element with an "attr" attribute will be a field (with an associated getter) in the Java class. Each structure can only contain one <data> element, and it is automatically assigned to a field called "data."

A description of a SNAC:
{{{#!xml
<snac>
  <ushort attr="family" />
  <ushort attr="type" />
  <ubyte attr="flag1" />
  <ubyte attr="flag2" />
  <uint attr="reqid" />
  <data />
  <!-- I think maybe nothing can go after that data element if its length is not specified; 
       then again, its length could be inferred in some cases -->
</snac>
}}}

A TLV chain:
{{{#!xml
<tlv-chain>
  <seq attr="tlvs">
    <tlv/>
  </seq>
</tlv-chain>
}}}

You'd access the TLV's using chain.getTlvs(), which would be of type Tlv[]. It would also have a constructor like TlvChain(Tlv[]).

A RateInfoSnac, maybe:

{{{#!xml
<rate-info-snac family="0x1" type="0x7">
  <uint id="numClasses"/>
  <seq attr="rate-infos" items="$numClasses">
    <rate-class-info/>
  </seq>
  <seq attr="rate-members" items="$numClasses">
    <rate-class-members/>
  </seq>
</rate-info-snac>
}}}

You'd get the rate information blocks with snac.getRateInfos() (a RateClassInfo[]). The constructor's arguments would be new RateInfoSnac(RateClassInfo[], RateClassMembers[]). The code generator would have to be smart to recognize that the two arrays have to have the same length...

 * How sould SNAC data formats be stored? Should there be a {{{rate-info-snac}}} that contains a {{{snac}}} element? I think that would get tedious

An AuthRequestSnac:

{{{#!xml
<auth-request-snac family="0x17" type="0x2">
  <tlv-chain>
    <attr name="tlvs">
      <tlv type="0x1">
        <ascii-string attr="screenname"/>
      </tlv>
      <tlv type="0x25">
        <data attr="encrypted-pass"/>
      </tlv>
      <tlv type="0x4c" present-attr="double-hashed"/>
      <tlv type="0xe">
        <ascii-string attr="country"/>
      </tlv>
      <tlv type="0xf">
        <ascii-string attr="lang"/>
      </tlv>
      <client-version-info attr="version-info"/>
    </attr>
  </tlv-chain>
</auth-request-snac>
}}}
```