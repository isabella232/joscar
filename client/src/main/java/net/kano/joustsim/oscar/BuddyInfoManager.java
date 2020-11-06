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
 *  File created by keith @ Jan 25, 2004
 *
 */

package net.kano.joustsim.oscar;

import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.CopyOnWriteArrayList;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.MiscTools;
import net.kano.joscar.flapcmd.SnacCommand;
import net.kano.joscar.snac.SnacRequestAdapter;
import net.kano.joscar.snac.SnacResponseEvent;
import net.kano.joscar.snac.ClientSnacProcessor;
import net.kano.joscar.snac.SnacRequest;
import net.kano.joscar.snaccmd.CapabilityBlock;
import net.kano.joscar.snaccmd.CertificateInfo;
import net.kano.joscar.snaccmd.DirInfo;
import net.kano.joscar.snaccmd.ExtraInfoBlock;
import net.kano.joscar.snaccmd.ExtraInfoData;
import net.kano.joscar.snaccmd.FullUserInfo;
import net.kano.joscar.snaccmd.ShortCapabilityBlock;
import net.kano.joscar.snaccmd.WarningLevel;
import net.kano.joscar.snaccmd.loc.GetInfoCmd;
import net.kano.joscar.snaccmd.icbm.SingleBuddyRequest;
import net.kano.joscar.snaccmd.error.SnacError;
import net.kano.joustsim.Screenname;
import net.kano.joustsim.oscar.oscar.service.Service;
import net.kano.joustsim.oscar.oscar.service.bos.MainBosServiceListener;
import net.kano.joustsim.oscar.oscar.service.bos.MainBosService;
import net.kano.joustsim.oscar.oscar.service.buddy.BuddyServiceListener;
import net.kano.joustsim.oscar.oscar.service.buddy.BuddyService;
import net.kano.joustsim.oscar.oscar.service.info.BuddyHashHolder;
import net.kano.joustsim.oscar.oscar.service.info.InfoServiceListener;
import net.kano.joustsim.oscar.oscar.service.info.InfoService;
import net.kano.joustsim.trust.BuddyCertificateInfo;
import org.jetbrains.annotations.NotNull;

import java.beans.PropertyChangeEvent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

public class BuddyInfoManager {
  private static final Logger LOGGER = Logger
      .getLogger(BuddyInfoManager.class.getName());

  private final AimConnection conn;
  private Map<Screenname, BuddyInfo> buddyInfos
      = new HashMap<Screenname, BuddyInfo>();
  private Map<BuddyHashHolder, BuddyCertificateInfo> cachedCertInfos
      = new HashMap<BuddyHashHolder, BuddyCertificateInfo>();

  private boolean initedBuddyService = false;
  private boolean initedInfoService = false;
  private boolean initedBosService = false;

  private final CopyOnWriteArrayList<GlobalBuddyInfoListener> listeners
      = new CopyOnWriteArrayList<GlobalBuddyInfoListener>();

  private BuddyInfoChangeListener pcl = new BuddyInfoChangeListener() {
    public void propertyChange(PropertyChangeEvent evt) {
      fireGlobalPropertyChangeEvent(evt);
    }

    public void receivedBuddyStatusUpdate(BuddyInfo info) {
      fireReceivedStatusEvent(info);
    }
  };

  public BuddyInfoManager(AimConnection conn) {
    DefensiveTools.checkNull(conn, "conn");

    this.conn = conn;
    conn.addOpenedServiceListener(new OpenedServiceListener() {
      public void openedServices(AimConnection conn,
          Collection<? extends Service> services) {
        initBuddyService();
        initInfoService();
        initBosService();
      }

      public void closedServices(AimConnection conn,
          Collection<? extends Service> services) {
      }
    });
    initBuddyService();
    initInfoService();
    initBosService();
  }

  public AimConnection getAimConnection() { return conn; }

  private synchronized void cacheCertInfo(BuddyCertificateInfo certInfo) {
    DefensiveTools.checkNull(certInfo, "certInfo");

    Screenname buddy = certInfo.getBuddy();
    ByteBlock hash = certInfo.getCertificateInfoHash();
    BuddyHashHolder holder = new BuddyHashHolder(buddy, hash);
    if (cachedCertInfos.containsKey(holder)) return;
    cachedCertInfos.put(holder, certInfo);
  }

  private void initBuddyService() {
    BuddyService bs = conn.getBuddyService();
    if (bs == null) return;

    synchronized (this) {
      if (initedBuddyService) return;
      initedBuddyService = true;
    }

    bs.addBuddyListener(new BuddyServiceListener() {
      public void gotBuddyStatus(BuddyService service, Screenname buddy,
          FullUserInfo info) {
        handleBuddyStatusUpdate(buddy, info);
      }

      public void buddyOffline(BuddyService service, Screenname buddy) {
        getBuddyInfoInstance(buddy).setOnline(false);
      }
    });
  }

  private void initInfoService() {
    InfoService infoService = conn.getInfoService();
    if (infoService == null) return;

    synchronized (this) {
      if (initedInfoService) return;
      initedInfoService = true;
    }

    infoService.addInfoListener(new InfoServiceListener() {
      public void handleDirectoryInfo(InfoService service, Screenname buddy,
          DirInfo info) {
        BuddyInfo buddyInfo = getBuddyInfoInstance(buddy);
        buddyInfo.setOnline(true);
        buddyInfo.setDirectoryInfo(info);
      }

      public void handleAwayMessage(InfoService service, Screenname buddy,
          String awayMsg) {
        BuddyInfo buddyInfo = getBuddyInfoInstance(buddy);
        buddyInfo.setOnline(true);
        buddyInfo.setAwayMessage(awayMsg);
      }

      public void handleUserProfile(InfoService service, Screenname buddy,
          String infoString) {
        BuddyInfo buddyInfo = getBuddyInfoInstance(buddy);
        buddyInfo.setOnline(true);
        buddyInfo.setUserProfile(infoString);
      }

      public void handleCertificateInfo(InfoService service, Screenname buddy,
          BuddyCertificateInfo certInfo) {
        LOGGER.fine("BuddyInfoManager got cert info for " + buddy);
        BuddyInfo buddyInfo = getBuddyInfoInstance(buddy);
        buddyInfo.setOnline(true);
        if (certInfo != null) cacheCertInfo(certInfo);
        buddyInfo.setCertificateInfo(certInfo);
      }

      public void handleInvalidCertificates(InfoService service,
          Screenname buddy, CertificateInfo origCertInfo, Throwable ex) {
      }
    });
  }

  private void initBosService() {
    MainBosService bos = conn.getBosService();
    if (bos == null) return;

    synchronized (this) {
      if (initedBosService) return;
      initedBosService = true;
    }

    bos.addMainBosServiceListener(new MainBosServiceListener() {
      public void handleYourInfo(MainBosService service,
          FullUserInfo userInfo) {
        handleBuddyStatusUpdate(conn.getScreenname(), userInfo);
      }

      public void handleYourExtraInfo(List<ExtraInfoBlock> extraInfos) {
        if (extraInfos != null) {
          handleExtraInfoBlocks(conn.getScreenname(), extraInfos);
        }
      }
    });
    final ClientSnacProcessor processor = bos.getOscarConnection()
        .getSnacProcessor();
    // mark people as offline when getting away msg fails twice in a row
    processor.addGlobalResponseListener(new SnacRequestAdapter() {
      public void handleResponse(SnacResponseEvent e) {
        SnacCommand cmd = e.getSnacCommand();
        if (!(cmd instanceof SnacError)) return;
        SnacError error = (SnacError) cmd;
        if (error.getErrorCode() != SnacError.CODE_USER_UNAVAILABLE) return;
        SnacCommand sent = e.getRequest().getCommand();
        if (!(sent instanceof SingleBuddyRequest)) return;

        SingleBuddyRequest request = (SingleBuddyRequest) sent;
        final Screenname sn = new Screenname(request.getScreenname());
        BuddyInfo info = getBuddyInfoInstance(sn);
        if (info.isOnBuddyList() || !info.isOnline()) return;

        LOGGER.info("I think " + sn + " might be offline after "
            + MiscTools.getClassName(sent) + " returned 'user unvailable'; "
            + "pinging user to make sure");
        processor.sendSnac(new SnacRequest(new GetInfoCmd(
            GetInfoCmd.FLAG_AWAYMSG, request.getScreenname()),
            new SnacRequestAdapter() {
          public void handleResponse(SnacResponseEvent snacResponseEvent) {
            SnacCommand cmd = snacResponseEvent.getSnacCommand();
            if (!(cmd instanceof SnacError)) return;

            SnacError error = (SnacError) cmd;
            if (error.getErrorCode() == SnacError.CODE_USER_UNAVAILABLE) {
              LOGGER.warning("Got two 'user unavailable' responses for " + sn
                  + ", marking as offline");
              getBuddyInfoInstance(sn).setOnline(false);
            }
          }
        }));
        info.setOnline(false);
      }
    });
  }

  public void addGlobalBuddyInfoListener(GlobalBuddyInfoListener l) {
    listeners.addIfAbsent(l);
  }

  public void removeGlobalBuddyInfoListener(GlobalBuddyInfoListener l) {
    listeners.remove(l);
  }

  private void handleBuddyStatusUpdate(Screenname buddy, FullUserInfo info) {
    BuddyInfo buddyInfo = getBuddyInfoInstance(buddy);

    buddyInfo.setOnline(true);
    Date onSince = info.getOnSince();
    if (onSince != null) buddyInfo.setOnlineSince(onSince);

    Boolean awayStatus = info.getAwayStatus();
    if (awayStatus != null) buddyInfo.setAway(awayStatus);
    
    long icqStatus = info.getIcqStatus();
    if (icqStatus != -1) buddyInfo.setIcqStatus(icqStatus);

    boolean mobile = false;
    List<CapabilityBlock> caps = info.getCapabilityBlocks();
    List<ShortCapabilityBlock> shortCaps = info.getShortCapabilityBlocks();
    if (caps != null || shortCaps != null) {
      int numLong = caps == null ? 0 : caps.size();
      int numShort = shortCaps == null ? 0 : shortCaps.size();

      List<CapabilityBlock> blocks = new ArrayList<CapabilityBlock>(
          numLong + numShort);
      if (caps != null) {
        blocks.addAll(caps);
      }
      if (shortCaps != null) {
        for (ShortCapabilityBlock shortCap : shortCaps) {
          blocks.add(shortCap.toCapabilityBlock());
        }
      }
      if (blocks.contains(CapabilityBlock.BLOCK_HIPTOP)) {
        mobile = true;
      }
      buddyInfo.setCapabilities(blocks);
    }

    ByteBlock certHash = info.getCertInfoHash();
    if (certHash != null) {
      if (certHash.getLength() == 0) certHash = null;
      buddyInfo.setCertificateInfo(
          getAppropriateCertificateInfo(buddy, certHash));
    }

    int idleMins = info.getIdleMins();
    Date idleSince;
    if (idleMins == -1) {
      idleSince = null;
    } else {
      int idlems = idleMins * 1000 * 60;
      idleSince = new Date(System.currentTimeMillis() - idlems);
    }
    buddyInfo.setIdleSince(idleSince);

    WarningLevel level = info.getWarningLevel();
    if (level != null) {
      int x10 = level.getX10Value();
      int rounder = (x10 % 10) >= 5 ? 1 : 0;
      int warningLevel = (x10 / 10) + rounder;
      buddyInfo.setWarningLevel(warningLevel);
    }

    List<ExtraInfoBlock> extraBlocks = info.getExtraInfoBlocks();
    if (extraBlocks != null) {
      handleExtraInfoBlocks(buddy, extraBlocks);
    }

    int flags = info.getFlags();
    mobile |= (flags & FullUserInfo.MASK_WIRELESS) != 0;
    buddyInfo.setMobile(mobile);
    buddyInfo.setRobot((flags & FullUserInfo.MASK_AB) != 0);
    buddyInfo.setAolUser((flags & FullUserInfo.MASK_AOL) != 0);

    buddyInfo.receivedBuddyStatusUpdate();
  }

  private void handleExtraInfoBlocks(Screenname buddy,
      List<ExtraInfoBlock> extraBlocks) {
    BuddyInfo buddyInfo = getBuddyInfo(buddy);
    
    // reset away message
    buddyInfo.setAwayMessage(null);
    
    for (ExtraInfoBlock block : extraBlocks) {
      int type = block.getType();
      ExtraInfoData data = block.getExtraData();
      if (type == ExtraInfoBlock.TYPE_ICONHASH) {
        buddyInfo.setIconHash(block.getExtraData());

      } else if (type == ExtraInfoBlock.TYPE_AVAILMSG) {
        String status = ExtraInfoData.readAvailableMessage(data);
        buddyInfo.setStatusMessage(status);

      } else if (type == ExtraInfoBlock.TYPE_ITUNES_URL) {
        String status = ExtraInfoData.readAvailableMessage(data);
        buddyInfo.setItunesUrl(status);
      }
    }
  }

  private synchronized BuddyCertificateInfo getAppropriateCertificateInfo(
      Screenname buddy, ByteBlock certHash) {
    BuddyCertificateInfo cached = getCachedCertificateInfo(buddy, certHash);
    if (cached != null) return cached;
    if (certHash == null) return null;

    return new BuddyCertificateInfo(buddy, certHash);
  }

  public synchronized BuddyCertificateInfo getCachedCertificateInfo(
      Screenname buddy, ByteBlock hash) {
    DefensiveTools.checkNull(buddy, "buddy");

    if (hash == null) return null;

    BuddyHashHolder holder = new BuddyHashHolder(buddy, hash);
    return cachedCertInfos.get(holder);
  }

  private synchronized @NotNull BuddyInfo getBuddyInfoInstance(
      Screenname buddy) {
    BuddyInfo info = buddyInfos.get(buddy);
    if (info == null) {
      info = new BuddyInfo(buddy);
      info.addPropertyListener(pcl);
      buddyInfos.put(buddy, info);
    }
    return info;
  }

  public synchronized @NotNull BuddyInfo getBuddyInfo(Screenname buddy) {
    return getBuddyInfoInstance(buddy);
  }

  private void fireGlobalPropertyChangeEvent(PropertyChangeEvent evt) {
    assert !Thread.holdsLock(this);

    BuddyInfo info = (BuddyInfo) evt.getSource();
    Screenname sn = info.getScreenname();

    for (GlobalBuddyInfoListener l : listeners) {
      l.buddyInfoChanged(this, sn, info, evt);
    }
  }

  private void fireReceivedStatusEvent(BuddyInfo info) {
    assert !Thread.holdsLock(this);

    Screenname sn = info.getScreenname();

    for (GlobalBuddyInfoListener l : listeners) {
      l.receivedStatusUpdate(this, sn, info);
    }
  }

  public synchronized Set<BuddyInfo> getKnownBuddyInfos() {
    return DefensiveTools.getUnmodifiableSetCopy(buddyInfos.values());
  }
}
