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
 *  File created by keith @ Jan 26, 2004
 *
 */

package net.kano.joustsim.oscar.oscar.service.icbm.secureim;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import net.kano.joustsim.trust.CertificatePairHolder;
import net.kano.joustsim.oscar.oscar.NoBuddyKeysException;
import net.kano.joscar.EncodedStringInfo;
import net.kano.joscar.MinimalEncoder;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class SecureAimEncoder extends SecureAimCodec {
    public synchronized byte[] encryptMsg(String msg)
            throws NoSuchProviderException, NoSuchAlgorithmException,
            CMSException, IOException, NoBuddyKeysException,
            NoLocalKeysException {

        if (getLocalKeys() == null) throw new NoLocalKeysException();
        CertificatePairHolder buddyCerts = getBuddyCerts();
        if (buddyCerts == null) throw new NoBuddyKeysException();

        X509Certificate recip = buddyCerts.getSigningCertificate();
        if (recip == null) throw new NoBuddyKeysException();
        
        byte[] signedDataBlock = cmsSignString(msg);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        try {
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recip));
        } catch (CertificateEncodingException e) {
            throw new CMSException("Invalid certificate", e);
        }
        CMSEnvelopedData envData = gen.generate(
                new CMSProcessableByteArray(signedDataBlock),
                new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).build());

        return envData.getEncoded();
    }

    protected synchronized byte[] cmsSignString(String msg) throws IOException,
            NoSuchProviderException, NoSuchAlgorithmException, CMSException {

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        OutputStreamWriter osw = new OutputStreamWriter(bout, StandardCharsets.US_ASCII);
        EncodedStringInfo encodeInfo = MinimalEncoder.encodeMinimally(msg);
        String charset = encodeInfo.getCharset().toLowerCase();
        osw.write("Content-Transfer-Encoding: binary\r\n"
                + "Content-Type: text/x-aolrtf; charset=" + charset + "\r\n"
                + "Content-Language: en\r\n"
                + "\r\n");
        osw.flush();
        bout.write(encodeInfo.getData());

        byte[] dataToSign = bout.toByteArray();
        byte[] signedData = signData(dataToSign);

        bout = new ByteArrayOutputStream();
        osw = new OutputStreamWriter(bout, StandardCharsets.US_ASCII);
        osw.write("Content-Transfer-Encoding: binary\r\n"
                + "Content-Type: application/pkcs7-mime; charset=us-ascii\r\n"
                + "Content-Language: en\r\n"
                + "\r\n");
        osw.flush();
        bout.write(signedData);

        return bout.toByteArray();
    }

    protected synchronized byte[] signData(byte[] dataToSign)
        throws CMSException, IOException {

        List<X509Certificate> certs = new ArrayList<>(1);
        certs.add(getLocalKeys().getSigningCertificate());
        CMSSignedDataGenerator sgen = new CMSSignedDataGenerator();
        try {
            ContentSigner signer = new JcaContentSignerBuilder(CMSSignedGenerator.DIGEST_MD5)
                .setProvider("BC")
                .build(getLocalKeys().getSigningKeys().getPrivateKey());
            sgen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                    .build(signer, getLocalKeys().getSigningCertificate()));
            sgen.addCertificates(new JcaCertStore(certs));
        } catch (OperatorCreationException | CertificateEncodingException e) {
            throw new CMSException("Failed to create signer", e);
        }

        CMSSignedData csd = sgen.generate(new CMSProcessableByteArray(dataToSign), true);
        return csd.getEncoded();
    }
}
