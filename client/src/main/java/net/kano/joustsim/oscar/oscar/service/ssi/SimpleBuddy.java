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

package net.kano.joustsim.oscar.oscar.service.ssi;

import net.kano.joscar.ssiitem.BuddyItem;
import net.kano.joscar.common.CopyOnWriteArrayList;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joustsim.Screenname;

class SimpleBuddy implements Buddy {
  private final SimpleBuddyList buddyList;

  private CopyOnWriteArrayList<BuddyListener> listeners
      = new CopyOnWriteArrayList<BuddyListener>();

  private final int itemId;
  private BuddyItem item;
  private boolean active = true;

  private Screenname screenname;
  private String alias;
  private String buddyComment;

  private int alertActionMask;
  private String alertSound;
  private int alertEventMask;
  private boolean awaitingAuthorization;

  SimpleBuddy(SimpleBuddyList list, BuddyItem item) {
    this.buddyList = list;

    this.itemId = item.getId();
    setItem(item);
  }

  public SimpleBuddyList getBuddyList() {
    return buddyList;
  }

  public BuddyItem getItem() {
    synchronized (getBuddyListLock()) {
      return item;
    }
  }

  public void setItem(BuddyItem item) {
    DefensiveTools.checkNull(item, "item");

    synchronized (getBuddyListLock()) {
      if (item.getId() != itemId) {
        throw new IllegalArgumentException("item " + item + " does not "
            + "match ID " + itemId);
      }
      this.item = item;
      screenname = new Screenname(item.getScreenname());
      alias = item.getAlias();
      alertActionMask = item.getAlertActionMask();
      alertSound = item.getAlertSound();
      alertEventMask = item.getAlertWhenMask();
      buddyComment = item.getBuddyComment();
      awaitingAuthorization = item.isAwaitingAuth();
    }
  }

  protected BuddyState saveState() {
    synchronized (getBuddyListLock()) {
      return new BuddyState();
    }
  }

  public void detectChanges(BuddyState oldState, BuddyState newState) {
    assert!Thread.holdsLock(this);

    Screenname oldSn = oldState.getScreenname();
    Screenname newSn = newState.getScreenname();
    if (!ChangeTools.areEqual(oldSn.getFormatted(), newSn.getFormatted())) {
      for (BuddyListener listener : listeners) {
        listener.screennameChanged(this, oldSn, newSn);
      }
    }
    String oldAlias = oldState.getAlias();
    String newAlias = newState.getAlias();
    if (!ChangeTools.areEqual(oldAlias, newAlias)) {
      for (BuddyListener listener : listeners) {
        listener.aliasChanged(this, oldAlias, newAlias);
      }
    }
    String oldComment = oldState.getBuddyComment();
    String newComment = newState.getBuddyComment();
    if (!ChangeTools.areEqual(oldComment, newComment)) {
      for (BuddyListener listener : listeners) {
        listener.buddyCommentChanged(this, oldComment, newComment);
      }
    }
    int oldAlertAction = oldState.getAlertActionMask();
    int newAlertAction = newState.getAlertActionMask();
    if (oldAlertAction != newAlertAction) {
      for (BuddyListener listener : listeners) {
        listener.alertActionChanged(this, oldAlertAction,
            newAlertAction);
      }
    }
    String oldAlertSound = oldState.getAlertSound();
    String newAlertSound = newState.getAlertSound();
    if (!ChangeTools.areEqual(oldAlertSound, newAlertSound)) {
      for (BuddyListener listener : listeners) {
        listener.alertSoundChanged(this, oldAlertSound, newAlertSound);
      }
    }
    int oldAlertEvent = oldState.getAlertEventMask();
    int newAlertEvent = newState.getAlertEventMask();
    if (oldAlertEvent != newAlertEvent) {
      for (BuddyListener listener : listeners) {
        listener.alertTimeChanged(this, oldAlertEvent, newAlertEvent);
      }
    }
    boolean oldAwaitingAuth = oldState.isAwaitingAuthorization();
    boolean newAwaitingAuth = newState.isAwaitingAuthorization();
    if (oldAwaitingAuth != newAwaitingAuth) {
      for (BuddyListener listener : listeners) {
        listener.awaitingAuthChanged(this, oldAwaitingAuth, newAwaitingAuth);
      }
    }
  }

  public void addBuddyListener(BuddyListener listener) {
    listeners.add(listener);
  }

  public void removeBuddyListener(BuddyListener listener) {
    listeners.remove(listener);
  }

  protected class BuddyState {
    private Screenname screenname;
    private String alias;
    private String buddyComment;

    private int alertActionMask;
    private String alertSound;
    private int alertEventMask;

    private boolean awaitingAuthorization;

    public BuddyState() {
      this.screenname = SimpleBuddy.this.screenname;
      this.alias = SimpleBuddy.this.alias;
      this.buddyComment = SimpleBuddy.this.buddyComment;
      this.alertActionMask = SimpleBuddy.this.alertActionMask;
      this.alertSound = SimpleBuddy.this.alertSound;
      this.alertEventMask = SimpleBuddy.this.alertEventMask;
      this.awaitingAuthorization = SimpleBuddy.this.awaitingAuthorization;
    }

    public Screenname getScreenname() {
      return screenname;
    }

    public String getAlias() {
      return alias;
    }

    public String getBuddyComment() {
      return buddyComment;
    }

    public int getAlertActionMask() {
      return alertActionMask;
    }

    public String getAlertSound() {
      return alertSound;
    }

    public int getAlertEventMask() {
      return alertEventMask;
    }

    public boolean isAwaitingAuthorization() {
      return awaitingAuthorization;
    }
  }

  private Object getBuddyListLock() {
    return buddyList.getLock();
  }

  public void setActive(boolean active) {
    synchronized (getBuddyListLock()) {
      this.active = active;
    }
  }

  public boolean isActive() {
    synchronized (getBuddyListLock()) {
      return active;
    }
  }

  public Screenname getScreenname() {
    synchronized (getBuddyListLock()) {
      return screenname;
    }
  }

  public String getAlias() {
    synchronized (getBuddyListLock()) {
      return alias;
    }
  }

  public int getAlertActionMask() {
    synchronized (getBuddyListLock()) {
      return alertActionMask;
    }
  }

  public String getAlertSound() {
    synchronized (getBuddyListLock()) {
      return alertSound;
    }
  }

  public int getAlertEventMask() {
    synchronized (getBuddyListLock()) {
      return alertEventMask;
    }
  }

  public String getBuddyComment() {
    synchronized (getBuddyListLock()) {
      return buddyComment;
    }
  }


  public boolean isAwaitingAuthorization() {
    synchronized (getBuddyListLock()) {
      return awaitingAuthorization;
    }
  }


  public String toString() {
    return "Buddy " + getScreenname() + " (alias " + getAlias() + ")";
  }
}
