/*
 *  Copyright (c) 2003, The Joust Project
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
 *  File created by keith @ Nov 13, 2003
 *
 */

package net.kano.joscardemo;

import net.kano.joscar.flap.AsynchronousFlapProcessor;
import net.kano.joscar.flap.FlapCommand;
import net.kano.joscar.flap.FlapPacketEvent;
import net.kano.joscar.flap.FlapPacketListener;
import net.kano.joscar.flap.FlapProcessor;
import net.kano.joscar.flapcmd.DefaultFlapCmdFactory;
import net.kano.joscar.flapcmd.LoginFlapCmd;
import net.kano.joscar.flapcmd.SnacCommand;
import net.kano.joscar.snac.ClientSnacProcessor;
import net.kano.joscar.snac.FamilyVersionPreprocessor;
import net.kano.joscar.snac.SnacPacketEvent;
import net.kano.joscar.snac.SnacPacketListener;
import net.kano.joscar.snac.SnacRequest;
import net.kano.joscar.snac.SnacRequestAdapter;
import net.kano.joscar.snac.SnacRequestListener;
import net.kano.joscar.snac.SnacResponseEvent;
import net.kano.joscar.snaccmd.DefaultClientFactoryList;
import net.kano.joscar.snaccmd.auth.AuthRequest;
import net.kano.joscar.snaccmd.auth.AuthResponse;
import net.kano.joscar.snaccmd.auth.ClientVersionInfo;
import net.kano.joscar.snaccmd.auth.KeyRequest;
import net.kano.joscar.snaccmd.auth.KeyResponse;

import java.io.IOException;
import java.net.Socket;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TutorialDemo {
    private static final ClientVersionInfo VER_AIM51 = new ClientVersionInfo(
            "AOL Instant Messenger, version 5.1.3036/WIN32",
            5, 1, 0, 3036, 239);

    private Socket socket;
    private FlapProcessor flapProcessor;
    private ClientSnacProcessor snacProcessor;
    private SnacRequestListener respListener;
    private Thread flapEventThread;

    private String screenname;
    private String password;

    public TutorialDemo(String screenname, String password) {
        this.screenname = screenname;
        this.password = password;
    }

    public void connect() throws IOException {
        // connect to the login server
        socket = new Socket("login.oscar.aol.com", 5190);

        // create SNAC and FLAP handlers
        flapProcessor = new AsynchronousFlapProcessor(socket);
        snacProcessor = new ClientSnacProcessor(flapProcessor);

        // these are important but not worth explaining now
        flapProcessor.setFlapCmdFactory(new DefaultFlapCmdFactory());
        snacProcessor.addPreprocessor(new FamilyVersionPreprocessor());
        snacProcessor.getCmdFactoryMgr().setDefaultFactoryList(
                new DefaultClientFactoryList());

        // create a response listener to listen for responses to SNAC's we send
        // during the login process
        respListener = new SnacRequestAdapter() {
            public void handleResponse(SnacResponseEvent e) {
                SnacCommand snacCmd = e.getSnacCommand();

                System.out.println("Got SNAC response: " + snacCmd);

                if (snacCmd instanceof KeyResponse) {
                    KeyResponse keyResponse = (KeyResponse) snacCmd;
                    AuthRequest authRequest = new AuthRequest(
                            screenname, password,
                            VER_AIM51, keyResponse.getKey());
                    snacProcessor.sendSnac(
                            new SnacRequest(authRequest, respListener));
                } else if (snacCmd instanceof AuthResponse) {
                    // ...
                }
            }
        };

        // create a FLAP packet listener to initialize the FLAP portion of the
        // connection
        flapProcessor.addPacketListener(new FlapPacketListener() {
            public void handleFlapPacket(FlapPacketEvent e) {
                FlapCommand flapCmd = e.getFlapCommand();

                System.out.println("Got FLAP command: " + flapCmd);

                if (flapCmd instanceof LoginFlapCmd) {
                    flapProcessor.sendFlap(new LoginFlapCmd());
                    snacProcessor.sendSnac(new SnacRequest(
                            new KeyRequest(screenname), respListener));
                }
            }
        });

        // create a SNAC packet listener to listen for any other packets (note
        // that on the login connection, this shouldn't actually get any
        // packets, since they're all SNAC responses; this is here to show you
        // how to do it)
        snacProcessor.addPacketListener(new SnacPacketListener() {
            public void handleSnacPacket(SnacPacketEvent e) {
                SnacCommand snacCmd = e.getSnacCommand();

                System.out.println("Got SNAC command: " + snacCmd);
            }
        });

        // FLAP packets can't be read if there's nothing to read them, so we
        // create a FLAP reading loop (which in turn reads SNAC's, and so on)
        flapEventThread = new Thread("FLAP Event Loop") {
            public void run() {
                try {
                    flapProcessor.runFlapLoop();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        flapEventThread.start();
    }


    public static void main(String[] args) {
        // enable logging, so we can see what's going on inside joscar
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.ALL);
        Logger logger = Logger.getLogger("net.kano.joscar");
        logger.addHandler(handler);
        logger.setLevel(Level.ALL);

        // create the demo object and try to connect
        TutorialDemo td = new TutorialDemo("myscreenname", "mypassword");
        try {
            td.connect();
        } catch (IOException e) {
            System.err.println("Error connecting to server or initializing "
                    + "joscar: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
