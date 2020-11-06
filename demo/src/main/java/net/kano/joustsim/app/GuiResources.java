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
 *  File created by keith @ Feb 5, 2004
 *
 */

package net.kano.joustsim.app;

import net.kano.joscar.common.DefensiveTools;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.UIManager;
import java.net.URL;

public final class GuiResources {
    private static final IconResourceHolder mediumCertificateIcon
            = new IconResourceHolder("icons/certificate-medium.png");
    private static final IconResourceHolder tinyCertificateIcon
            = new IconResourceHolder("icons/certificate-tiny.png");
    private static final IconResourceHolder mediumColoredLockIcon
            = new IconResourceHolder("icons/lock-color-medium.png");
    private static final IconResourceHolder tinyColoredLockIcon
            = new IconResourceHolder("icons/lock-color-tiny.png");
    private static final IconResourceHolder tinyGrayLockIcon
            = new IconResourceHolder("icons/lock-gray-tiny.png");
    private static final IconResourceHolder tinyGrayInsecureLockIcon
            = new IconResourceHolder("icons/lock-gray-insecure-tiny.png");
    private static final IconResourceHolder mediumSignerIcon
            = new IconResourceHolder("icons/signer-medium.png");
    private static final IconResourceHolder tinySignerIcon
            = new IconResourceHolder("icons/signer-tiny.png");
    private static final IconResourceHolder tinyProgramIcon
            = new IconResourceHolder("icons/program-tiny.png");
    private static final IconResourceHolder tinyKeystoreIcon
            = new IconResourceHolder("icons/keystore-tiny.png");

    private static final LFIconHolder errorIcon
            = new LFIconHolder("OptionPane.errorIcon");
    private static final LFIconHolder informationIcon
            = new LFIconHolder("OptionPane.informationIcon");
    private static final LFIconHolder warningIcon
            = new LFIconHolder("OptionPane.warningIcon");

    private GuiResources() { }

    private static ImageIcon getIconFromResource(String name) {
        URL url = GuiResources.class.getClassLoader().getResource(name);

        if (url == null) return null;
        else return new ImageIcon(url);
    }

    public static ImageIcon getMediumCertificateIcon() {
        return mediumCertificateIcon.getIcon();
    }

    public static ImageIcon getTinyCertificateIcon() {
        return tinyCertificateIcon.getIcon();
    }

    public static ImageIcon getMediumColoredLockIcon() {
        return mediumColoredLockIcon.getIcon();
    }

    public static ImageIcon getMediumSignerIcon() {
        return mediumSignerIcon.getIcon();
    }

    public static ImageIcon getTinySignerIcon() {
        return tinySignerIcon.getIcon();
    }

    public static ImageIcon getTinyProgramIcon() {
        return tinyProgramIcon.getIcon();
    }

    public static ImageIcon getTinyColoredLockIcon() {
        return tinyColoredLockIcon.getIcon();
    }

    public static ImageIcon getTinyGrayLockIcon() {
        return tinyGrayLockIcon.getIcon();
    }

    public static ImageIcon getTinyGrayInsecureLockIcon() {
        return tinyGrayInsecureLockIcon.getIcon();
    }

    public static ImageIcon getTinyKeystoreIcon() {
        return tinyKeystoreIcon.getIcon();
    }

    public static Icon getErrorIcon() {
        return errorIcon.getIcon();
    }

    public static Icon getInformationIcon() {
        return informationIcon.getIcon();
    }

    public static Icon getWarningIcon() {
        return warningIcon.getIcon();
    }

    public static String getFullProgramName() { return "Joust Secure IM Lite"; }

    public static String getProjectName() { return "Joust"; }

    public static String getProgramWebsiteUrl() {
        return "http://joust.kano.net";
    }

    private static final class IconResourceHolder {
        private final String resource;
        private ImageIcon icon = null;

        public IconResourceHolder(String resource) {
            DefensiveTools.checkNull(resource, "resource");

            this.resource = resource;
        }

        public synchronized ImageIcon getIcon() {
            if (icon == null) icon = getIconFromResource(resource);
            return icon;
        }
    }
    private static final class LFIconHolder {
        private final String property;

        public LFIconHolder(String property) {
            DefensiveTools.checkNull(property, "property");

            this.property = property;
        }

        public synchronized Icon getIcon() {
            return UIManager.getIcon(property);
        }
    }
}
