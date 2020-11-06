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

package net.kano.joustsim.oscar.oscar.service.icbm.ft.controllers;

import net.kano.joscar.common.CopyOnWriteArrayList;
import net.kano.joscar.MiscTools;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.events.RvConnectionEvent;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.FailedStateInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.FailureEventInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.StateInfo;
import net.kano.joustsim.oscar.oscar.service.icbm.ft.state.SuccessfulStateInfo;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractStateController implements StateController {
  private static final Logger LOGGER = Logger
      .getLogger(AbstractStateController.class.getName());

  private CopyOnWriteArrayList<ControllerListener> listeners
      = new CopyOnWriteArrayList<ControllerListener>();
  private StateInfo endState = null;

  public void addControllerListener(ControllerListener listener) {
    listeners.addIfAbsent(listener);
  }

  public void removeControllerListener(ControllerListener listener) {
    listeners.remove(listener);
  }

  protected void fireSucceeded(StateInfo stateInfo) {
    assert !Thread.holdsLock(this);

    fireEvent(stateInfo);
  }

  protected void fireFailed(Exception e) {
    assert !Thread.holdsLock(this);

    LOGGER.log(Level.SEVERE, "Error in " + this + ":", e);

    fireEvent(new ExceptionStateInfo(e));
  }

  protected void fireFailed(RvConnectionEvent e) {
    fireEvent(new FailureEventInfo(e));
  }

  protected void fireFailed(FailedStateInfo info) {
    fireEvent(info);
  }

  private void fireEvent(StateInfo e) {
    assert !Thread.holdsLock(this);

    boolean succeeded = e instanceof SuccessfulStateInfo;
    boolean failed = e instanceof FailedStateInfo;
    if (!succeeded && !failed) {
      throw new IllegalArgumentException("invalid state " + e
          + ": it must be either SuccessfulStateInfo or "
          + "FailedStateInfo");
    }

    synchronized (this) {
      if (endState != null) {
        LOGGER.info("State controller " + this
            + " tried to set new end state " + e + " but it was "
            + "already " + endState);
        return;
      }
      endState = e;
    }
    LOGGER.log(Level.FINE, "New state for " + getClass().getName() + ": " + e);
    if (succeeded) {
      SuccessfulStateInfo successfulStateInfo = (SuccessfulStateInfo) e;

      for (ControllerListener listener : listeners) {
        listener.handleControllerSucceeded(this, successfulStateInfo);
      }
    } else {
      FailedStateInfo failedStateInfo = (FailedStateInfo) e;

      for (ControllerListener listener : listeners) {
        listener.handleControllerFailed(this, failedStateInfo);
      }
    }
  }

  public synchronized StateInfo getEndStateInfo() { return endState; }

  public String toString() {
    return MiscTools.getClassName(this);
  }
}
