/*
 *  Copyright (c) 2004, The Joust Project
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
 *  File created by keith @ Jan 15, 2004
 *
 */

package net.kano.joustsim.oscar.oscar;

import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.flapcmd.SnacCommand;
import net.kano.joscar.flapcmd.LoginFlapCmd;
import net.kano.joscar.snac.SnacPacketEvent;
import net.kano.joscar.snaccmd.conn.ServerReadyCmd;

public class BasicConnection extends OscarConnection {
  private ByteBlock cookie = null;

  public BasicConnection(String host, int port) {
    super(host, port);
  }

  protected void beforeConnect() {
    if (getCookie() == null) {
      throw new IllegalStateException("You must set a cookie for a "
          + "BasicConnection to connect");
    }
  }

  public synchronized ByteBlock getCookie() { return cookie; }

  public synchronized void setCookie(ByteBlock cookie) {
    checkFieldModify();
    DefensiveTools.checkNull(cookie, "cookie");

    this.cookie = cookie;
  }


  protected void beforeServicesConnected() {
    sendFlap(new LoginFlapCmd(getCookie()));
  }

  protected void handleSnacPacket(SnacPacketEvent snacPacketEvent) {
    try {
      SnacCommand snac = snacPacketEvent.getSnacCommand();

      if (snac instanceof ServerReadyCmd) {
        ServerReadyCmd src = (ServerReadyCmd) snac;

        setSnacFamilies(src.getSnacFamilies());
      }
    } finally {
      // we call this last in case it was a ServerReadyCmd, and we want it to
      // be processed by the BosService
      super.handleSnacPacket(snacPacketEvent);
    }
  }
}
