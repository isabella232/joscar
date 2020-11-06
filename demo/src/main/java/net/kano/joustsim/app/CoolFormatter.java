/*
 *  Copyright (c) 2005, The Joust Project
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
 */

package net.kano.joustsim.app;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.Date;
import java.text.DateFormat;
import java.io.StringWriter;
import java.io.PrintWriter;

public class CoolFormatter extends Formatter {
    private final DateFormat formatter
            = DateFormat.getTimeInstance(DateFormat.SHORT);

    public String format(LogRecord record) {
        String clname = record.getSourceClassName();
        String shname = clname.substring(clname.lastIndexOf('.') + 1);
        Throwable thrown = record.getThrown();
        StringWriter sw = null;
        if (thrown != null) {
            sw = new StringWriter();
            thrown.printStackTrace(new PrintWriter(sw));
        }
        return "[" + formatter.format(new Date(record.getMillis()))
                + " " + record.getLevel() + "] "
                + shname + ": "
                + record.getMessage() + (sw == null ? ""
                : sw.getBuffer().toString()) + "\n";
    }
}
