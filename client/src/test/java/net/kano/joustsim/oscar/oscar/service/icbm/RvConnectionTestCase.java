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

import junit.framework.TestCase;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.StateInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.StreamInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnectionEventListener;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnection;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.RvConnectionState;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.OutgoingConnectionController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.StateController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.ConnectedController;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers.ControllerListener;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.events.RvConnectionEvent;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.events.StartingControllerEvent;
import net.kano.joustsim.TestTools;
import net.kano.joscar.rvproto.rvproxy.RvProxyReadyCmd;
import net.kano.joscar.rvproto.rvproxy.RvProxyAckCmd;
import net.kano.joscar.rvcmd.RvConnectionInfo;
import net.kano.joscar.snaccmd.CapabilityBlock;

import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.Callable;
import java.net.UnknownHostException;
import java.net.InetAddress;

public abstract class RvConnectionTestCase extends TestCase {
  public static final CapabilityBlock MOCK_CAPABILITY
      = new CapabilityBlock(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);

  protected abstract MockRvConnection getConnection();

  protected void generateRequestAndWaitForStream() {
    assertEndWasStream(generateRequestAndRun());
  }

  protected void assertEndWasStream(StateInfo end) {
    assertTrue("End was " + end, end instanceof StreamInfo);
  }

  protected StateInfo generateRequestAndRun() {
    MockRvConnection conn = getConnection();
    conn.getRvSessionHandler().handleIncomingRequest(null, new GenericRequest());
    return conn.waitForCompletion();
  }

  protected MockProxyConnector getDirectedToProxyConnector() {
    return new MockProxyConnector(
        new MockProxyConnection(new RvProxyReadyCmd()));
  }

  protected void assertSentRvs(int numreqs, int accepts, int rejects) {
    MockRvConnection connection = getConnection();
    MockRvRequestMaker maker = connection.getRvSessionInfo().getRequestMaker();
    List<Integer> requests = maker.getSentRequests();
    assertEquals("Unexpected request count", numreqs, requests.size());
    for (int i = 0; i < numreqs; i++) {
      int expected = i + getBaseOutgoingRequestId();
      assertTrue("Got req#" + requests.get(i) + ", expected >=" + expected,
          expected <= requests.get(i));
    }
    assertEquals("Unexpected accept count", accepts, maker.getAcceptCount());
    assertEquals("Unexpected reject count", rejects, maker.getRejectCount());
  }

  protected abstract int getBaseOutgoingRequestId();

  protected MockProxyConnector getInitiateProxyConnector() {
    try {
      return new MockProxyConnector(new MockProxyConnection(
          new RvProxyAckCmd(InetAddress.getByName("9.9.9.9"), 1000),
          new RvProxyReadyCmd()));
    } catch (UnknownHostException e) {
      throw new RuntimeException(e);
    }
  }

  protected StateInfo simulateBuddyRedirectionAndWait(
      MockIncomingRvConnection conn, MockConnector hangConnector,
      RvConnectionInfo conninfo) {
    MockRvSessionHandler handler = conn.getRvSessionHandler();
    handler.handleIncomingRequest(null, new GenericRequest());
    hangConnector.waitForConnectionAttempt();
    handler.handleIncomingRequest(null, new GenericRequest(2,
        conninfo));
    return conn.waitForCompletion();
  }

  protected void addNopConnector() {
    getConnection().addEventListener(new RvConnectionEventListener() {
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
            ogc.setConnector(new NopConnector());
          }
        }
      }
    });
  }

  protected void assertHitOnce(Class<?> cls) {
    assertNotNull(TestTools.findOnlyInstance(getConnection().getHitControllers(),
        cls));
  }

  protected MyFutureTask setConnectedWaiter() {
    final MyFutureTask connectedWaiter = new MyFutureTask();
    getConnection().setConnectedController(new NotifyingConnectedController(connectedWaiter));
    return connectedWaiter;
  }

  protected void assertDidntHit(Class<?> cls) {
    assertNull(TestTools.findOnlyInstance(getConnection().getHitControllers(), cls));
  }

  protected static InetAddress ip(String addr) throws UnknownHostException {
    return InetAddress.getByName(addr);
  }

  protected void assertHitMultiple(Class<? extends StateController> cls,
      int count) {
    assertEquals(count, TestTools.findInstances(getConnection().getHitControllers(),
        cls).size());
  }

  protected static class MyFutureTask extends FutureTask<Object> {
    public MyFutureTask() {
      super(new Callable<Object>() {
        public Object call() throws Exception {
          return null;
        }
      });
    }

    public void set(Object v) {
      super.set(v);
    }
  }

  private static class NotifyingConnectedController implements ConnectedController {
    private final MyFutureTask connectedWaiter;

    public NotifyingConnectedController(MyFutureTask connectedWaiter) {
      this.connectedWaiter = connectedWaiter;
    }

    public boolean isConnected() {
      return true;
    }

    public boolean didConnect() {
      return true;
    }

    public void start(RvConnection transfer, StateController last) {
      connectedWaiter.set(null);
    }

    public void addControllerListener(ControllerListener listener) {
    }

    public void removeControllerListener(ControllerListener listener) {
    }

    public StateInfo getEndStateInfo() {
    //        try {
    //          return new SocketStreamInfo(null);
    //        } catch (IOException e) {
    //          throw new IllegalStateException(e);
    //        }
      return null;
    }

    public void stop() {
    }
  }
}
