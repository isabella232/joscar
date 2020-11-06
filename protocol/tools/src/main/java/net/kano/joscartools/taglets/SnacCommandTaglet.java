/*
 *  Copyright (c) 2002-2003, The Joust Project
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions 
 *  are met:
 *
 *  - Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *  - Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *    the documentation and/or other materials provided with the 
 *    distribution. 
 *  - Neither the name of the Joust Project nor the names of its 
 *    contributors may be used to endorse or promote products derived 
 *    from this software without specific prior written permission. 
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 *  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 *  File created by keith @ Apr 1, 2003
 *
 */

package net.kano.joscartools.taglets;

import com.sun.javadoc.Tag;
import com.sun.tools.doclets.Taglet;

import java.util.Map;

/**
 * A javadoc taglet that provides a <code>@snac.cmd</code> tag to indicate the
 * SNAC command and subtype of a SNAC command class.
 */
public class SnacCommandTaglet implements Taglet {
    /**
     * Registers this taglet with the given taglet map.
     *
     * @param tagletMap a taglet map with which to register this taglet
     */
    public static void register(Map<String,SnacCommandTaglet> tagletMap) {
        SnacCommandTaglet instance = new SnacCommandTaglet();
        tagletMap.put(instance.getName(), instance);
    }

    public boolean inField() { return false; }

    public boolean inConstructor() { return false; }

    public boolean inMethod() { return false; }

    public boolean inOverview() { return false; }

    public boolean inPackage() { return false; }

    public boolean inType() { return true; }

    public boolean isInlineTag() { return false; }

    public String getName() { return "snac.cmd"; }

    public String toString(Tag tag) {
        String text = tag.text();
        int space = text.indexOf(' ');
        String command = text.substring(0, space);
        String subtype = text.substring(space + 1);

        return "<dt title=\"The SNAC family and subtype of this SNAC " +
                "command\"><b>SNAC command type:</b></dt><dd>Family <span " +
                "title=\"SNAC family\"><code>" + command +
                "</code></span>, command <span title=\"SNAC command " +
                "subtype\"><code>" + subtype + "</code></span></dd>";
    }

    public String toString(Tag[] tags) {
        if (tags.length == 0) return null;
        else if (tags.length == 1) return toString(tags[0]);
        else throw new IllegalArgumentException("more than one snac.cmd tag");
    }
}
