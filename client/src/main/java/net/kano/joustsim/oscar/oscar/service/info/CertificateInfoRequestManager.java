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
 *  File created by keith @ Feb 7, 2004
 *
 */

package net.kano.joustsim.oscar.oscar.service.info;

import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.flapcmd.SnacCommand;
import net.kano.joscar.snaccmd.CertificateInfo;
import net.kano.joscar.snaccmd.InfoData;
import net.kano.joscar.snaccmd.loc.GetInfoCmd;
import net.kano.joustsim.Screenname;
import net.kano.joustsim.trust.BuddyCertificateInfo;
import net.kano.joustsim.trust.TrustTools;

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class CertificateInfoRequestManager
    extends UserInfoRequestManager<CertificateInfo> {
  private static final Logger LOGGER = Logger
      .getLogger(CertificateInfoRequestManager.class.getName());

  public CertificateInfoRequestManager(MutableInfoService service) {
    super(service);
  }

  protected SnacCommand generateSnacCommand(Screenname sn) {
    LOGGER.fine("generating cert request for " + sn);
    return new GetInfoCmd(GetInfoCmd.FLAG_CERT, sn.getFormatted());
  }

  protected void callListener(InfoResponseListener listener, Screenname sn,
      CertificateInfo certInfo) {
    BuddyCertificateInfo bci = extractBuddyCertificateInfo(sn, certInfo);
    listener.handleCertificateInfo(getService(), sn, bci);
  }

  private BuddyCertificateInfo extractBuddyCertificateInfo(Screenname sn,
      CertificateInfo certInfo) {
    if (certInfo == null) return null;

    ByteBlock signingData;
    ByteBlock encryptionData;
    if (certInfo.isCommon()) {
      signingData = certInfo.getCommonCertData();
      encryptionData = certInfo.getCommonCertData();
    } else {
      signingData = certInfo.getSignCertData();
      encryptionData = certInfo.getEncCertData();
    }
    if (signingData == null || encryptionData == null) {
      fireInvalidCertsException(sn, null, certInfo);
      return null;
    }

    X509Certificate signing;
    X509Certificate encryption;
    try {
      signing = TrustTools.decodeCertificate(signingData);
      encryption = TrustTools.decodeCertificate(encryptionData);
    } catch (Exception e) {
      fireInvalidCertsException(sn, e, certInfo);
      return null;
    }

    return new BuddyCertificateInfo(sn,
        ByteBlock.wrap(CertificateInfo.getCertInfoHash(certInfo)),
        encryption, signing);
  }

  private void fireInvalidCertsException(Screenname sn,
      Exception e, CertificateInfo origCertInfo) {
    for (Object o : getListeners(sn)) {
      InfoResponseListener listener = (InfoResponseListener) o;
      listener.handleInvalidCertificates(getService(), sn, origCertInfo,
          e);
    }
  }

  protected CertificateInfo getDesiredValue(InfoData infodata) {
    return infodata.getCertificateInfo();
  }
}
