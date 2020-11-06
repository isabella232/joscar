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
 *  File created by keith @ Mar 3, 2003
 *
 */

package net.kano.joscar.snaccmd.ssi;

import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.MiscTools;
import net.kano.joscar.flapcmd.SnacPacket;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A SNAC command used to acknowledge the modification of the user's
 * server-stored data. Normally sent in response to {@link CreateItemsCmd},
 * {@link ModifyItemsCmd}, and {@link DeleteItemsCmd}.
 *
 * @snac.src server
 * @snac.cmd 0x13 0x0e
 *
 * @see CreateItemsCmd
 * @see ModifyItemsCmd
 * @see DeleteItemsCmd
 */
public class SsiDataModResponse extends SsiCommand {
    /**
     * A result code indicating that the requested change was made successfully.
     */
    public static final int RESULT_SUCCESS = 0x0000;
    /**
     * A result code indicating that one or more of the items requested to be
     * modified or deleted does not exist and thus cannot be modified or
     * deleted.
      */
    public static final int RESULT_NO_SUCH_ITEM = 0x0002;
    /**
     * A result code indicating that the client attempted to create a second
     * {@linkplain net.kano.joscar.ssiitem.RootItem group list}. Sometimes this
     * code is also used when attempting to add an item with the same ID but
     * different type as an existing item.
     */
    public static final int RESULT_CANT_ADD_ANOTHER_ROOT_GROUP = 0x0003;
    /**
     * A result code indicating that one or more of the items requested to be
     * created cannot be because an item with the same ID already exists.
     */
    public static final int RESULT_ID_TAKEN = 0x000a;
    /**
     * A result code indicating that one or more of the requested items cannot
     * be created because the {@linkplain SsiRightsCmd maximum number of items}
     * of that type has been reached.
     */
    public static final int RESULT_MAX_ITEMS = 0x000c;
    /**
     * A result code indicating that ICQ users cannot be added to an AIM buddy
     * list.
     *
     * @see net.kano.joscar.snaccmd.CapabilityBlock#BLOCK_ICQCOMPATIBLE
     */
    public static final int RESULT_NO_ICQ = 0x000d;
    /**
     * A result code indicating that (ICQ) authorization is required before the
     * user can be added to the list. This normally only happens while adding
     * ICQ
     */
    public static final int RESULT_ICQ_AUTH_REQUIRED = 0x000e;
    /**
     * A result code indicating that the given SSI item contained invalid data.
     * This result code is returned when a client attempts to add a buddy whose
     * screenname is longer than the screenname length limit. 
     */
    public static final int RESULT_BAD_FORMAT = 0x0010;

    /** The result codes. */
    private final int[] results;

    /**
     * Generates a new SSI data modification response command from the
     * given incoming SNAC packet.
     *
     * @param packet an incoming SSI data modification response packet
     */
    protected SsiDataModResponse(SnacPacket packet) {
        super(CMD_MOD_ACK);

        DefensiveTools.checkNull(packet, "packet");

        ByteBlock snacData = packet.getData();

        int items = snacData.getLength() / 2;
        results = new int[items];

        for (int i = 0; i < items; i++) {
            results[i] = BinaryTools.getUShort(snacData, i*2);
        }
    }

    /**
     * Creates a new outgoing SSI modification response with the given result
     * codes.
     *
     * @param results a list of result codes (like {@link #RESULT_SUCCESS})
     */
    public SsiDataModResponse(int[] results) {
        super(CMD_MOD_ACK);

        this.results = DefensiveTools.getSafeMinArrayCopy(results,
                "results", 0);
    }

    /**
     * Returns the result codes associated with this SSI modification response.
     * Each result code is normally one of the {@linkplain #RESULT_SUCCESS
     * <code>RESULT_<i>*</i></code> constants} defined in this class.
     *
     * @return the result codes sent in this SSI modification response
     */
    public final int[] getResults() {
        return (int[]) results.clone();
    }

    public void writeData(OutputStream out) throws IOException {
        for (int result : results) {
            BinaryTools.writeUShort(out, result);
        }
    }

    public String toString() {
        StringBuffer string = new StringBuffer();
        string.append("SsiDataModAck: results=");

        for (int i = 0; i < results.length; i++) {
            int result = results[i];

            string.append("0x");
            string.append(Integer.toHexString(result));

            String field = MiscTools.findIntField(SsiDataModResponse.class,
                    result, "RESULT_.*");
            if (field != null) {
                string.append(" (");
                string.append(field);
                string.append(")");
            }

            if (i != results.length - 1) string.append(", ");
        }

        return string.toString();
    }
}