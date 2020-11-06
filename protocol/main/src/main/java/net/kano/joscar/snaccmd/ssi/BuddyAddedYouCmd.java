package net.kano.joscar.snaccmd.ssi;

import java.io.*;

import java.nio.charset.StandardCharsets;
import net.kano.joscar.*;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.flapcmd.*;

/**
 * This is the "you-were-added" message meaning that somebody
 * added you to his/her list.
 *
 * @author Damian Minkov
 */
public class BuddyAddedYouCmd
    extends SsiCommand
{
    private String uin;

    public BuddyAddedYouCmd(SnacPacket packet)
    {
        super(CMD_YOU_WERE_ADDED_RECV);

        ByteBlock data = packet.getData();

        int offset = 0;
        short strLen = LEBinaryTools.getUByte(data, offset);
        offset++;

        ByteBlock field = data.subBlock(offset, strLen);
        uin = OscarTools.getString(field, StandardCharsets.US_ASCII);
    }

    public void writeData(OutputStream out) throws IOException{}

    public String getUin()
    {
        return uin;
    }
}
