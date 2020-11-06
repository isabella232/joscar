package net.kano.joscar.snaccmd.ssi;

import java.io.*;

import java.nio.charset.StandardCharsets;
import net.kano.joscar.*;
import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.flapcmd.*;

/**
 * Sending authorization reply
 *
 * @author Damian Minkov
 */
public class AuthReplyCmd
    extends SsiCommand
{
    private static int FLAG_AUTH_ACCEPTED = 1;
    private static int FLAG_AUTH_DECLINED = 0;

    private String uin = null;
    private String reason = null;
    private boolean accepted = false;

    public AuthReplyCmd(String uin, String reason, boolean accepted)
    {
        super(CMD_AUTH_REPLY);

        this.uin = uin;
        this.reason = reason;
        this.accepted = accepted;
    }

    /**
     * Incoming Command reply for our Authorization request
     * @param packet SnacPacket the incoming packet
     */
    public AuthReplyCmd(SnacPacket packet)
    {
        super(CMD_AUTH_REPLY_RECV);

        ByteBlock messageData = packet.getData();
        // parse data
        int offset = 0;
        short uinLen = BinaryTools.getUByte(messageData, offset++);
        uin = OscarTools.getString(messageData.subBlock(offset, uinLen), StandardCharsets.US_ASCII);
        offset += uinLen;

        accepted =
            BinaryTools.getUByte(messageData, offset++) == FLAG_AUTH_ACCEPTED;

        int reasonLen = BinaryTools.getUShort(messageData, offset);
        offset += 2;
        reason = OscarTools.getString(messageData.subBlock(offset, reasonLen), StandardCharsets.US_ASCII);
    }

    /**
     * Writes this command's SNAC data block to the given stream.
     *
     * @param out the stream to which to write the SNAC data
     * @throws IOException if an I/O error occurs
     */
    public void writeData(OutputStream out) throws IOException
    {
        byte[] uinBytes = BinaryTools.getAsciiBytes(uin);
        BinaryTools.writeUByte(out, uinBytes.length);
        out.write(uinBytes);

        if (accepted)
        {
            BinaryTools.writeUByte(out, FLAG_AUTH_ACCEPTED);
        }
        else
        {
            BinaryTools.writeUByte(out, FLAG_AUTH_DECLINED);
        }

        if (reason == null)
        {
            reason = "";
        }

        byte[] reasonBytes = BinaryTools.getAsciiBytes(reason);
        BinaryTools.writeUShort(out, reasonBytes.length);
        out.write(reasonBytes);
    }

    public String getSender()
    {
        return uin;
    }

    public String getReason()
    {
        return reason;
    }

    public boolean isAccepted()
    {
        return accepted;
    }
}
