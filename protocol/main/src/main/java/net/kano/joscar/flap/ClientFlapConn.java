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
 *  File created by keith @ Mar 6, 2003
 *
 */

package net.kano.joscar.flap;

import net.kano.joscar.net.ClientConn;
import net.kano.joscar.net.ClientConnEvent;
import net.kano.joscar.net.ClientConnListener;
import net.kano.joscar.net.ClientConnStreamHandler;
import net.kano.joscar.net.ConnDescriptor;

import java.io.IOException;
import java.net.Socket;

import net.kano.joscar.logging.Logger;
import net.kano.joscar.logging.LoggingSystem;

/**
 * A simpler interface to using an outgoing clientside FLAP connection. This
 * class essentially runs a {@link FlapProcessor} atop a {@link ClientConn}; you
 * should read each's documentation thoroughly.
 * <br>
 * <br>
 * Note that this class adds a connection listener and sets the stream handler
 * of the its parent <code>ClientConn</code>.
 */
public class ClientFlapConn extends ClientConn {
    /** The FLAP processor that this object uses. */
    private AsynchronousFlapProcessor flapProcessor;

    /**
     * Creates a client FLAP connection. The given host and port will be
     * used to connect to when {@link #connect} is called.
     *
     * @param cd an object describing the destination host and port for this
     *        connection
     */
    public ClientFlapConn(ConnDescriptor cd) {
        super(cd);

        init();
    }


    /**
     * Initializes the super <code>ClientConn</code> by adding a connection
     * listener and setting the stream handler.
     */
    private final void init() {
        flapProcessor = new AsynchronousFlapProcessor();
		
		setStreamHandler(new ClientConnStreamHandler() {
            public void handleStream(ClientConn conn, Socket socket)
                    throws IOException {
                flapProcessor.runFlapLoop();
            }
        });

        addConnListener(new ClientConnListener() {
            public void stateChanged(ClientConnEvent e) {
                State newState = e.getNewState();
                if (newState == ClientConn.STATE_CONNECTED) {
					LoggingSystem.getLogger(ClientFlapConn.class.getName()).logFine(newState.toString());

                    try {
						if (flapProcessor == null) {
							flapProcessor = new AsynchronousFlapProcessor();
							LoggingSystem.getLogger(ClientFlapConn.class.getName()).logFine("Created " + flapProcessor);
						}
						
                        flapProcessor.attachToSocket(getSocket());
                    } catch (IOException e1) {
                        processError(e1);

                        return;
                    }
                } else if (newState == ClientConn.STATE_NOT_CONNECTED
                        || newState == ClientConn.STATE_FAILED) {
					LoggingSystem.getLogger(ClientFlapConn.class.getName()).logFine(newState.toString() + "so breaking down " + flapProcessor);

					/* Breaking down the flapProcessor will also detach it */
					flapProcessor.breakdown();
					flapProcessor = null;
                }
            }
        });
    }

	protected void finalize() throws Throwable {
		try {
			LoggingSystem.getLogger(ClientFlapConn.class.getName()).logFine("finalize()");
		} finally {
			super.finalize();
		}
	}
	
    /**
     * Returns the FLAP processor that is running on this connection.
     *
     * @return this connection's FLAP processor
     */
    public final FlapProcessor getFlapProcessor() { return flapProcessor; }

    public String toString() {
        return "ClientFlapConn: "
                + "flapProcessor=" + flapProcessor;
    }
}