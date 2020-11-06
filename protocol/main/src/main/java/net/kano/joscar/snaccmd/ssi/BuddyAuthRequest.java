package net.kano.joscar.snaccmd.ssi;

import net.kano.joscar.OscarTools;
import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.StringBlock;
import net.kano.joscar.flapcmd.SnacPacket;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;

public class BuddyAuthRequest extends SsiCommand {
    private final String screenname;
    private final @Nullable String message;

    /**
     * Incoming Command Requesting our authorization
     * @param packet SnacPacket incoming packet
     */
    public BuddyAuthRequest(SnacPacket packet) {
        super(CMD_AUTH_REQUEST_RECV);
        ByteBlock data = packet.getData();
        StringBlock sn = OscarTools.readScreenname(data);
        if (sn != null) {
            screenname = sn.getString();
            ByteBlock rest = data.subBlock(sn.getTotalSize());
            int msglen = BinaryTools.getUShort(rest, 0);
            message = BinaryTools.getUtf8String(rest.subBlock(2, msglen));
        } else {
            screenname = null;
            message = null;
        }
    }
    /**
     * Command requesting authorization
     * @param sn screenname
     * @param msg the request reason
     */
    public BuddyAuthRequest(String sn, @Nullable String msg) {
        super(CMD_AUTH_REQ);
        this.screenname = sn;
        this.message = msg;
    }

    public void writeData(OutputStream out) throws IOException {
        OscarTools.writeScreenname(out, screenname);
        byte[] data = message == null
                ? new byte[0]
                : BinaryTools.getUtf8Bytes(message);
        BinaryTools.writeUShort(out, data.length);
        out.write(data);
        // it ends with 3 nulls
        BinaryTools.writeUByte(out, 0);
        BinaryTools.writeUShort(out, 0);
    }

    public String getMessage()
    {
        return message;
    }

    public String getScreenname()
    {
        return screenname;
    }
}
