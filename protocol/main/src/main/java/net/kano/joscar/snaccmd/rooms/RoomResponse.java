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
 *  File created by keith @ Feb 26, 2003
 *
 */

package net.kano.joscar.snaccmd.rooms;

import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.flapcmd.SnacPacket;
import net.kano.joscar.snaccmd.ExchangeInfo;
import net.kano.joscar.snaccmd.FullRoomInfo;
import net.kano.joscar.tlv.Tlv;
import net.kano.joscar.tlv.TlvChain;
import net.kano.joscar.tlv.TlvTools;

import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Collection;

/**
 * A SNAC command used to respond to every possible request or query made in the
 * chat room navigation family.
 * <br>
 * <br>
 * Normally this command only contains either a {@linkplain #getRoomInfo room
 * information block} <i>or</i> {@linkplain #getMaxRooms a maximum room value}
 * &amp; {@linkplain #getExchangeInfos a set of exchange information blocks}.
 * <br>
 * <br>
 * This command is normally sent in response to each of {@link JoinRoomCmd},
 * {@link ExchangeInfoReq}, {@link RoomRightsRequest}, and {@link RoomInfoReq}.
 *
 * @snac.src server
 * @snac.cmd 0x0d 0x09
 */
public class RoomResponse extends RoomCommand {
    /**
     * A TLV type containing the maximum number of rooms in which a user can
     * chat simultaneously.
     */
    private static final int TYPE_MAX_ROOMS = 0x0002;
    /** A TLV type containing an exchange information block. */
    private static final int TYPE_EXCHANGE_INFO = 0x0003;
    /** A TLV type containing chat room information. */
    private static final int TYPE_ROOM_INFO = 0x0004;

    /**
     * The maximum number of rooms in which a user can simultaneously be a
     * member.
     */
    private final int maxRooms;
    /** A set of exchange information blocks. */
    private final List<ExchangeInfo> exchangeInfos;
    /** A chat room information block. */
    private final FullRoomInfo roomInfo;

    /**
     * Generates a chat room navigation response command from the given incoming
     * SNAC command.
     *
     * @param packet an incoming chat room navigation family response
     */
    protected RoomResponse(SnacPacket packet) {
        super(CMD_ROOM_RESPONSE);

        DefensiveTools.checkNull(packet, "packet");

        ByteBlock snacData = packet.getData();

        TlvChain chain = TlvTools.readChain(snacData);

        Tlv maxRoomTlv = chain.getLastTlv(TYPE_MAX_ROOMS);

        if (maxRoomTlv == null) {
            maxRooms = -1;
        } else {
            maxRooms = BinaryTools.getUByte(maxRoomTlv.getData(), 0);
        }

        List<ExchangeInfo> exchangeList = new LinkedList<ExchangeInfo>();
        for (Tlv exchangeTlv : chain.getTlvs(TYPE_EXCHANGE_INFO)) {
            ByteBlock exTlvBlock = exchangeTlv.getData();

            ExchangeInfo exchange = ExchangeInfo.readExchangeInfo(exTlvBlock);
            if (exchange != null) exchangeList.add(exchange);
        }

        if (exchangeList.isEmpty()) {
            exchangeInfos = null;
        } else {
            exchangeInfos = exchangeList;
        }

        Tlv roomInfoTlv = chain.getLastTlv(TYPE_ROOM_INFO);

        if (roomInfoTlv == null) {
            roomInfo = null;
        } else {
            ByteBlock roomInfoBlock = roomInfoTlv.getData();

            roomInfo = FullRoomInfo.readRoomInfo(roomInfoBlock);
        }
    }

    /**
     * Creates a new outgoing room information response only containing the
     * given room information block.
     *
     * @param roomInfo the room information block to send in this response
     */
    public RoomResponse(FullRoomInfo roomInfo) {
        this(-1, null, roomInfo);
    }

    /**
     * Creates a new outgoing room information response containing only the
     * given maximum number of rooms and list of exchange information blocks.
     *
     * @param maxRooms the maximum number of rooms in which a user can
     *        simultaneously reside
     * @param exchangeInfos a list of exchange information blocks
     */
    public RoomResponse(int maxRooms, Collection<ExchangeInfo> exchangeInfos) {
        this(maxRooms, exchangeInfos, null);
    }

    /**
     * Creates a new outgoing room information response with the given maximum
     * number of rooms, exchange information blocks, and chat room information
     * block.
     *
     * @param maxRooms the maximum number of rooms in which a user can
     *        simultaneously reside
     * @param exchangeInfos a list of exchange information blocks
     * @param roomInfo a room information block
     */
    public RoomResponse(int maxRooms, Collection<ExchangeInfo> exchangeInfos,
            FullRoomInfo roomInfo) {
        super(CMD_ROOM_RESPONSE);

        DefensiveTools.checkRange(maxRooms, "maxRooms", -1);

        this.maxRooms = maxRooms;
        this.exchangeInfos = DefensiveTools.getUnmodifiableCopy(exchangeInfos);
        this.roomInfo = roomInfo;
    }

    /**
     * Returns the maximum number of rooms in which a user can simultaneously
     * reside. Note that this will be <code>-1</code> if this value was not
     * sent.
     *
     * @return the maximum number of rooms in which a user can reside at one
     *         time
     */
    public final int getMaxRooms() {
        return maxRooms;
    }

    /**
     * Returns the set of chat exchange information blocks that was sent in
     * this response, or <code>null</code> if this field was not sent.
     *
     * @return the list of chat exchange information blocks sent in this
     *         response
     */
    public final List<ExchangeInfo> getExchangeInfos() {
        return exchangeInfos;
    }

    /**
     * Returns the room information block sent in this response, or
     * <code>null</code> if none was sent.
     *
     * @return the room information block sent in this response
     */
    //TODO: what fields does the fullroominfo normally contain? not all of them.
    public final FullRoomInfo getRoomInfo() {
        return roomInfo;
    }

    public void writeData(OutputStream out) throws IOException {
        if (maxRooms != -1) {
            Tlv.getUShortInstance(TYPE_MAX_ROOMS, maxRooms).write(out);
        }
        if (exchangeInfos != null) {
            for (int i = 0; i < exchangeInfos.size(); i++) {
                new Tlv(TYPE_EXCHANGE_INFO,
                        ByteBlock.createByteBlock(exchangeInfos.get(i))).write(out);
            }
        }
        if (roomInfo != null) {
            new Tlv(TYPE_ROOM_INFO, ByteBlock.createByteBlock(roomInfo))
                    .write(out);
        }
    }

    public String toString() {
        return "RoomResponse: " +
                "maxRooms=" + maxRooms +
                ", exchangeInfos="
                + (exchangeInfos == null ? -1 : exchangeInfos.size()) +
                ", roomInfo=" + roomInfo;
    }
}
