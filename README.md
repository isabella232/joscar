README - joscar 0.9.3
AOL Instant Messenger protocol library for Java
(C) 2002-2004 The Joust Project

# ABOUT JOSCAR

joscar is an extensible low-level Java interface into AOL Instant Messenger's
OSCAR protocol from both the client and the server side.  The joscar library 
aims to provide implementations of individual commands as well as higher-level 
classes for easily managing data structures in the most common ways.

While joscar was designed mainly to be a client library, much of the
functionality necessary to implement an AIM server is there.  All commands and
data structures can be both read in from and written out to a stream of bytes.

joscar depends heavily on features only available in the Java 1.4 class
libraries, such as nio's Charset classes and regular expressions.

The joscar source code is released under a BSD-style license, which means you
are free to do whatever you please with it as long as you don't hold the Joust
Project accountable.  For legal details, please see the LICENSE file included 
with this distribution.

# ABOUT THE JOUST PROJECT

The Joust Project is a set of three subprojects aiming to provide a Java
interface to AOL Instant Messenger's Oscar protocol on three levels:

   - as an end user of AOL's (or another party's) instant messaging services
   - as a client developer for the above
   - for other more low-level purposes (developing an Oscar server, etc.)

Three separate components are planned for these three purposes:

   - Joust, a fully featured AIM client, building upon
   - jouscar, a high-level client interface to AIM, building upon
   - joscar, a low-level library for managing the raw data structures involved
     in an Oscar connection.

For more information regarding the status of these sub-projects, or to download 
releases, please visit the Joust Project web site (http://joust.kano.net/).

# OBTAINING JOSCAR

You can obtain the latest joscar release, as well as previous versions of the
library, from the Joust Project web site (http://joust.kano.net/), or from the 
Joust Project SourceForge project page (http://sf.net/projects/joustim).

If you like working with bleeding-edge code, you may sync with the joscar CVS
trunk hosted on SourceForge.  For instructions, please see the UPDATING file
included with this distribution.

# CONTACTING THE JOUST PROJECT

For any questions or general technical support issues, or if you're interested
in becoming a developer for the Joust Project, please send mail to 
<joust@kano.net>.

For the latest development and release news, please visit the Joust Project's 
web site (http://joust.kano.net/).  There, you can find information about the
various sub-projects, download releases, browse the CVS tree, read the
developers' weblog, and discuss the Joust Project with other developers.
Of particular interest is the developers' weblog, which is an invaluable
resource for anyone tracking Joust development (http://joust.kano.net/weblog/).

Bug reports, suggestions, and code contributions are appreciated and may be 
submitted by way of SourceForge (http://sf.net/projects/joustim/).  Use the 
Tracker tool to post bugs and suggestions, and use the Patches system to
submit code.

# FURTHER READING

You should have received the following files with your joscar distribution.
If not, you may download an official joscar release from the Joust Project web
site (http://joust.kano.net/).

   - README:  This file, which gives some general information about joscar and
     the Joust Project.

   - RELNOTES:  The release notes, showing what's new and different in this
     joscar release, as well as what's changed in prior releases.

   - LICENSE:  The Joust Project license, describing the ways in which you may
     use joscar and the joscar source code.

   - UPDATING:  Instructions on getting the latest joscar source code from the
     SourceForge CVS repository.

   - BUILDING:  A quick guide to building joscar binaries and documentation 
     using the Apache Project's ant tool (http://ant.apache.org/).

   - USING:  A quick guide to using the joscar library and the bundled 
     JoscarTester program.

Additionally, your joscar distribution may include the Javadoc API reference
in the docs/api/ directory.  The latest copy of this documentation is available 
on the Joust Project web site (http://joust.kano.net/joscar/docs/api/).  If
you are using joscar in your projects, you should read this documentation, as
it contains important development information.

Your joscar distribution may also include the howto guide in the docs/howto/
directory.  The latest copy of this documentation is available on the Joust
Project web site (http://joust.kano.net/joscar/docs/howto/).  The howto is a
brief overview of the Oscar login process, and will have larger scope and far
more depth in future iterations.

# ACKNOWLEDGMENTS

The Joust Project would like to thank Mark Doliner and Sean Egan of the Gaim
Project (http://gaim.sf.net/) for their assistance in explaining parts of the
Oscar protocol.

Huge thanks to Sam Stephenson for designing and hosting the website, writing
various materials distributed with joscar, and for lots of help debugging and
other things like that.

Thanks go to Ka-Hing Cheung for help with setting up the project's CVS 
repository on SourceForge.

Thanks to Elias Ross for some neat performance enhancements and various other
rather important bug reports.

Thanks to David Walluck of daim (http://daim.dev.java.net) for help with
implementing the rate-limiting algorithm as well as with figuring out
Trillian's Secure IM protocol.

Thanks to Doug Lea for the several classes from his concurrency package used in
joscar and lots of miscellaneous Java help.

Thanks to Ludovic LANGE for his rather indirect, but still important help in
figuring out Trillian's Secure IM protocol.

Thanks to David Hook of BouncyCastle (http://bouncycastle.org) for a great deal
of help in figuring out the format of AIM's encrypted IM data block and for 
promptly fixing the problems the joscar demo was having with BouncyCastle.

Thanks to Stephen Flynn for help implementing functionality to join chat rooms
to which one had been invited.

Thanks to Tim Dierks for a great deal of help figuring out and understanding
the encrypted IM/file transfer/direct IM/chat rooms protocols.

Thanks to Tal Liron for submitting a bunch of joscar-as-server fixes.

If you have contributed to joscar and are not listed here, please forgive our
oversight and send mail to <joscar@kano.net>.
