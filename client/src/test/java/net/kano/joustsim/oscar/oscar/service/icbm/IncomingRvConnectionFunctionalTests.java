/*
 * Copyright (c) 2006, The Joust Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the Joust Project nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * File created by keithkml
 */

package net.kano.joustsim.oscar.oscar.service.icbm;

import net.kano.joscar.rvcmd.RvConnectionInfo;
import net.kano.joscar.rvproto.rvproxy.RvProxyCmd;
import net.kano.joustsim.TestTools;
import static net.kano.joustsim.TestTools.findInstances;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.ConnectionType;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.DefaultRvConnectionEventListener;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnection;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnectionEventListener;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnectionState;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.TimeoutHandler;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.AbstractConnectionController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.ConnectToProxyForIncomingController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.OutgoingConnectionController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.ProxyConnection;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.ProxyConnector;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.RedirectConnectionController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.RedirectToProxyController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.StateController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.TimeoutableController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.events.RvConnectionEvent;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.events.StartingControllerEvent;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.SocketStreamInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.StateInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.StreamInfo;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class IncomingRvConnectionFunctionalTests extends RvConnectionTestCase {
  private MockIncomingRvConnection conn;

  protected void setUp() throws Exception {
    conn = new MockIncomingRvConnection();
  }

  protected void tearDown() throws Exception {
    conn = null;
  }

  protected MockRvConnection getConnection() {
    return conn;
  }

  protected int getBaseOutgoingRequestId() {
    return 2;
  }

  public void testLanConnection() {
    addNopConnector();
    generateRequestAndWaitForStream();
    assertTrue(TestTools.findOnlyInstance(conn.getHitControllers(),
        OutgoingConnectionController.class).getTimeoutType()
        == ConnectionType.LAN);
    assertSentRvs(0, 1, 0);
  }

  public void testInternetConnection() {
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof OutgoingConnectionController) {
            OutgoingConnectionController ogc
                = (OutgoingConnectionController) controller;
            ConnectionType type = ogc.getTimeoutType();
            if (type == ConnectionType.LAN) {
              ogc.setConnector(new FailConnector());

            } else if (type == ConnectionType.INTERNET) {
              ogc.setConnector(new NopConnector());

            } else {
              throw new IllegalStateException();
            }
          }
        }
      }
    });
    generateRequestAndWaitForStream();
    assertOnlyHit(ConnectionType.LAN, ConnectionType.INTERNET);
    assertSentRvs(0, 1, 0);
  }

  public void testProxyConnection() {
    conn.addEventListener(new RvConnectionEventListener() {
      public void handleEventWithStateChange(RvConnection transfer,
          RvConnectionState state, RvConnectionEvent event) {
      }

      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof OutgoingConnectionController) {
            OutgoingConnectionController ogc
                = (OutgoingConnectionController) controller;
            ogc.setConnector(new NeverConnector(ogc.getConnector()));

          } else if (controller instanceof ConnectToProxyForIncomingController) {
            ConnectToProxyForIncomingController proxyconn
                = (ConnectToProxyForIncomingController) controller;
            proxyconn.setConnector(getDirectedToProxyConnector());
          }
        }
      }
    });
    generateRequestAndWaitForStream();
    assertNotNull(TestTools.findOnlyInstance(conn.getHitControllers(),
        ConnectToProxyForIncomingController.class));
    assertSentRvs(0, 1, 0);
  }

  public void testRetryLastController() {
    final StateController[] second = new StateController[1];
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      private boolean hadFirst = false;
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event).getController();
          if (controller instanceof OutgoingConnectionController
              || controller instanceof RedirectConnectionController) {
            AbstractConnectionController oc
                = (AbstractConnectionController) controller;
            oc.setConnector(new HangConnector());
            
          } else if (controller instanceof RedirectToProxyController) {
            RedirectToProxyController pc
                = (RedirectToProxyController) controller;
            if (hadFirst) {
              second[0] = pc;
              pc.setConnector(getInitiateProxyConnector());

            } else {
              hadFirst = true;
              pc.setConnector(new HangProxyConnector());
            }
          }
        }
      }
    });
    conn.setTimeoutHandler(new TimeoutHandler() {
      public void startTimeout(TimeoutableController controller) {
        if (controller != second[0]) controller.cancelIfNotFruitful(0);
      }

      public void pauseTimeout(TimeoutableController controller) {
      }

      public void unpauseTimeout(TimeoutableController controller) {
      }
    });
    assertEndWasStream(generateRequestAndRun());
    assertNotNull(second[0]);
    assertHitMultiple(OutgoingConnectionController.class, 2);
    assertHitMultiple(RedirectToProxyController.class, 2);
    MockRvRequestMaker maker = getConnection().getRvSessionInfo().getRequestMaker();
    int reqs = maker.getSentRequests().size();
    // there might be only 2 requests because the timeout happens in a different
    // thread than the controller, so the controller might send the request
    // before the timeout hits
    assertTrue("Unexpected request count", reqs >= 2 && reqs <= 3);
    assertEquals("Unexpected accept count", 1, maker.getAcceptCount());
    assertEquals("Unexpected reject count", 0, maker.getRejectCount());
  }

  public void testWeRedirect() {
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof OutgoingConnectionController) {
            OutgoingConnectionController ogc
                = (OutgoingConnectionController) controller;
            ogc.setConnector(new FailConnector());

          } else if (controller instanceof RedirectConnectionController) {
            RedirectConnectionController redir
                = (RedirectConnectionController) controller;
            redir.setConnector(new PassiveNopConnector());
          }
        }
      }
    });
    StateInfo end = generateRequestAndRun();

    assertTrue("End was " + end, end instanceof StreamInfo);
    assertOnlyHit(ConnectionType.LAN, ConnectionType.INTERNET);
    assertHitOnce(RedirectConnectionController.class);
    assertSentRvs(1, 1, 0);
  }

  public void testWeRedirectPassiveFails() {
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof OutgoingConnectionController
              || controller instanceof RedirectConnectionController) {
            AbstractConnectionController ogc
                = (AbstractConnectionController) controller;
            ogc.setConnector(new FailConnector());

          } else if (controller instanceof RedirectToProxyController) {
            RedirectToProxyController redir
                = (RedirectToProxyController) controller;
            redir.setConnector(getInitiateProxyConnector());
          }
        }
      }
    });
    StateInfo end = generateRequestAndRun();

    assertTrue("End was " + end, end instanceof StreamInfo);
    assertOnlyHit(ConnectionType.LAN, ConnectionType.INTERNET);
    assertHitOnce(RedirectConnectionController.class);
    assertHitOnce(RedirectToProxyController.class);
    assertSentRvs(2, 1, 0);
  }

  public void testBuddyRedirects() throws UnknownHostException {
    final HangConnector hangConnector = new HangConnector();
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof OutgoingConnectionController
              || controller instanceof RedirectConnectionController) {
            AbstractConnectionController ogc
                = (AbstractConnectionController) controller;
            try {
              InetAddress internalip = conn.getRvSessionInfo().getConnectionInfo()
                  .getInternalIP();
              if (internalip.equals(ip("40.40.40.40"))) {
                ogc.setConnector(new NopConnector());
              } else {
                ogc.setConnector(hangConnector);
              }
            } catch (UnknownHostException e) {
              throw new IllegalArgumentException(e);
            }
          }
        }
      }
    });
    RvConnectionInfo conninfo = new RvConnectionInfo(
        ip("40.40.40.40"),
        ip("41.41.41.41"), null, 10, false, false);
    StateInfo end = simulateBuddyRedirectionAndWait(conn, hangConnector, conninfo);

    assertTrue("End was " + end, end instanceof StreamInfo);
    assertOnlyHit(ConnectionType.LAN, ConnectionType.LAN);
    assertSentRvs(0, 2, 0);
  }

  public void testBuddyRedirectsToProxy() throws UnknownHostException {
    final HangConnector hangConnector = new HangConnector();
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event)
              .getController();
          if (controller instanceof AbstractConnectionController) {
            AbstractConnectionController ogc
                = (AbstractConnectionController) controller;
            try {
              if (ip("60.60.60.60").equals(
                  conn.getRvSessionInfo().getConnectionInfo().getProxyIP())) {
                ogc.setConnector(getDirectedToProxyConnector());
              } else {
                ogc.setConnector(hangConnector);
              }
            } catch (UnknownHostException e) {
              throw new IllegalArgumentException(e);
            }
          }
        }
      }
    });
    RvConnectionInfo conninfo = RvConnectionInfo.createForOutgoingProxiedRequest(
        ip("60.60.60.60"), 10);
    StateInfo end = simulateBuddyRedirectionAndWait(conn, hangConnector, conninfo);

    assertTrue("End was " + end, end instanceof StreamInfo);
    List<OutgoingConnectionController> controllers
        = findInstances(conn.getHitControllers(), OutgoingConnectionController.class);
    assertEquals(1, controllers.size());
    assertTrue(controllers.get(0).getTimeoutType() == ConnectionType.LAN);
    assertNotNull(TestTools.findOnlyInstance(conn.getHitControllers(),
        ConnectToProxyForIncomingController.class));
    assertSentRvs(0, 2, 0);
  }

  public void testBuddyRedirectsAfterFinished()
      throws UnknownHostException {
    addNopConnector();
    generateRequestAndWaitForStream();
    conn.getRvSessionHandler().handleIncomingRequest(null,
        new GenericRequest(2, new RvConnectionInfo(
            ip("1.2.3.4"),
            ip("5.6.7.8"), null, 500, false, false)));
    assertSentRvs(0, 1, 0);
  }

  public void testBuddyRedirectsDuringTransfer()
      throws UnknownHostException, ExecutionException, InterruptedException {
    addNopConnector();
    MyFutureTask waiter = setConnectedWaiter();
    conn.getRvSessionHandler().handleIncomingRequest(null, new GenericRequest());
    assertSentRvs(0, 1, 0);
    List<StateController> hit = conn.getHitControllers();
    StateController last = hit.get(hit.size() - 1);
    waiter.get();
    conn.getRvSessionHandler().handleIncomingRequest(null,
        new GenericRequest(2, new RvConnectionInfo(
            ip("1.2.3.4"),
            ip("5.6.7.8"), null, 500, false, false)));
    assertSame("Redirect during transfer should not change controller",
        // -2 to ignore the mock connection connected controller
        last, hit.get(hit.size() - 2));
    assertSentRvs(0, 1, 0);
  }

  public void testBuddyRedirectsBeforeWeAccept()
      throws UnknownHostException, ExecutionException, InterruptedException {
    conn.setAutoMode(null);
    addNopConnector();
    conn.getRvSessionHandler().handleIncomingRequest(null, new GenericRequest());
    assertSentRvs(0, 0, 0);
    conn.getRvSessionHandler().handleIncomingRequest(null,
        new GenericRequest(2, new RvConnectionInfo(
            ip("1.2.3.4"),
            ip("5.6.7.8"), null, 500, false, false)));
    assertSentRvs(0, 0, 0);
    assertDidntHit(OutgoingConnectionController.class);
  }

  public void testBuddyRedirectsBeforeWeAcceptThenConnect()
      throws UnknownHostException, ExecutionException, InterruptedException {
    conn.setAutoMode(null);
    final boolean[] fail = new boolean[1];
    final boolean[] succeed = new boolean[1];
    final HangConnector hanger = new HangConnector();
    conn.addEventListener(new DefaultRvConnectionEventListener() {
      public void handleEvent(RvConnection transfer, RvConnectionEvent event) {
        if (event instanceof StartingControllerEvent) {
          StateController controller = ((StartingControllerEvent) event).getController();
          if (controller instanceof OutgoingConnectionController) {
            OutgoingConnectionController ogc
                = (OutgoingConnectionController) controller;
            String addr = conn.getRvSessionInfo().getConnectionInfo().getInternalIP()
                .getHostAddress();
            if (addr.equals("1.1.1.1")) {
              fail[0] = true;
              throw new IllegalStateException("Should not connect to 1.1.1.1");

            } else if (addr.equals("2.2.2.2")) {
              succeed[0] = true;
              ogc.setConnector(hanger);
            }
          }
        }
      }
    });
    conn.getRvSessionHandler().handleIncomingRequest(null, new GenericRequest(
        new RvConnectionInfo(ip("1.1.1.1"), null, null, 500,
            false, false)));
    assertSentRvs(0, 0, 0);
    assertFalse(fail[0]);
    assertFalse(succeed[0]);

    conn.getRvSessionHandler().handleIncomingRequest(null, new GenericRequest(2,
        new RvConnectionInfo(ip("2.2.2.2"), null, null, 500,
            false, false)));
    assertSentRvs(0, 0, 0);
    assertFalse(fail[0]);
    assertFalse(succeed[0]);

    conn.accept();
    hanger.waitForConnectionAttempt();
    assertFalse(fail[0]);
    assertTrue(succeed[0]);

    assertNotNull(TestTools.findOnlyInstance(conn.getHitControllers(),
        OutgoingConnectionController.class));
  }

  public void testRedirectAfterRejectNeverAccepted()
      throws UnknownHostException {
    conn.setAutoMode(null);
    addNopConnector();
    MockIncomingRvSessionHandler handler = conn.getRvSessionHandler();
    handler.handleIncomingRequest(null, new GenericRequest());
    conn.reject();
    handler.handleIncomingRequest(null, new GenericRequest(2,
        new RvConnectionInfo(ip("2.2.2.2"), null, null, 500,
            false, false)));
    assertTrue(conn.getHitControllers().isEmpty());
    assertSentRvs(0, 0, 1);
  }

  public void testWeImmediatelyReject() {
    conn.setAutoMode(AutoMode.REJECT);
    StateInfo end = generateRequestAndRun();

    assertNull(end);
    assertTrue(conn.getHitControllers().isEmpty());
    assertSentRvs(0, 0, 1);
  }

  private void assertOnlyHit(ConnectionType... array) {
    List<OutgoingConnectionController> controllers = findInstances(
        conn.getHitControllers(), OutgoingConnectionController.class);
    assertEquals(array.length, controllers.size());
    for (int i = 0; i < array.length; i++) {
      assertEquals("Controller #" + (i+1), array[i],
          controllers.get(i).getTimeoutType());
    }
  }

  private class HangProxyConnector implements ProxyConnector {
    private <E> E hang() {
      Object o = new Object();
      synchronized(o) {
        try {
          o.wait();
        } catch (InterruptedException e) {
        }
      }
      throw new IllegalStateException();
    }

    public ProxyConnection getProxyConnection() {
      return new ProxyConnection() {
        public RvProxyCmd readPacket() throws IOException {
          return hang();
        }

        public void sendProxyPacket(RvProxyCmd initCmd)
            throws IOException {
          hang();
        }
      };
    }

    public InetAddress getIpAddress() throws IOException {
      return InetAddress.getLocalHost();
    }

    public int getConnectionPort() {
      return 343;
    }

    public SocketStreamInfo createStream() throws IOException {
      return hang();
    }

    public void checkConnectionInfo() throws Exception {
    }

    public void prepareStream() throws IOException {
    }
  }
}