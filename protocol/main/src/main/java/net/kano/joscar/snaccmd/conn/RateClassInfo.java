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
 *  File created by keith @ Feb 21, 2003
 *
 */

package net.kano.joscar.snaccmd.conn;

import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.common.Writable;
import net.kano.joscar.snac.CmdType;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.List;

/**
 * A data structure containing rate limiting information for a specific "class"
 * of SNAC commands.
 *
 * <h2> Introduction to Rates </h2>
 *
 * A rate class identifies a set of SNAC commands and limitations on how fast
 * any sequence of those commands can be sent to the server. For example, one
 * rate class normally contains the <i>outgoing ICBM</i> command and the <i>info
 * request</i> command. You may have noticed that sometimes WinAIM will tell you
 * you can't look at someone's info because your rate is too high; this is why.
 * Gaim, of course, simply tells you to stop talking so fast. Good one, Gaim.
 *
 * <h2> The <code>RateClassInfo</code> Fields </h2>
 *
 * <dl>
 * <dt><code>windowSize</code></dt>
 * <dd>The number of previously sent commands that will be included in
 * the calculation of your current "rate average" (this value varies from
 * rate class to rate class; normally ranges from <code>10</code> to
 * <code>60</code>)</dd>
 * <dt><code>currentAvg</code>
 * <dd>Your current "rate average," which attempts to resemble a moving average
 * of the times between each of your last <code><i>windowSize</i></code>
 * commands</dd>
 * <dt><code>warnAvg</code></dt>
 * <dd>The "rate average" that will put you into the yellow part of
 * WinAIM's rate limiting bar (normally <code>5000</code> ms)</dd>
 * <dt><code>limitedAvg</code></dt>
 * <dd>The "rate average" under which you will be "rate limited" until your
 * rate average is back above <code>clearAvg</code> (normally <code>4000</code>
 * ms)</dd>
 * <dt><code>clearAvg</code></dt>
 * <dd>The "rate average" above which you will stop being rate limited, if you
 * are currently limited; this is normally equal to <code>warnAvg</code> plus
 * <code>100</code> ms, or <code>5100</code> ms</dd>
 * <dt><code>disconnectAvg</code></dt>
 * <dd>The "rate average" below which you will be disconnected from the server
 * (normally <code>3000</code> ms)</dd>
 * <dt><code>max</code></dt>
 * <dd>The maximum value for a rate average (normally <code>6000</code> ms)</dd>
 * </dl>
 *
 * <h2> Handling Rate-Related SNAC Commands </h2>
 *
 * The values described above can be used to keep an accurate rate average for a
 * rate class as follows:
 * <br>
 * <br>
 * Upon initial connection, the average should be ignored: all commands can be
 * sent as quickly as possible until a {@link RateAck} is sent.
 * <br>
 * <br>
 * Upon receiving a {@link RateInfoCmd}, the current rate for each rate class
 * within should be set to that rate class's {@linkplain #getMax() maximum rate
 * average}. Note that a {@linkplain #getCurrentAvg current average} is sent,
 * but should be <b>ignored</b> in the initial <code>RateInfoCmd</code>.
 * <br>
 * <br>
 * Upon receiving a {@link RateChange}, nothing must be modified (unless the
 * maximum rate average has been decreased and the current rate is now above
 * it). You may want to set your current average to the given "current average,"
 * but this is not advised, as the rate change command may have been sent in
 * response to a command sent several commands ago (due to network lag). A good
 * way to do this might be to only set your rate average to the given "current
 * average" only if the given current average is lower than your client's
 * computed average. This should be the most conservative and thus reliable way
 * to handle rate changes.
 *
 * <h2> Computing the Current Rate </h2>
 *
 * Now the important part: how to compute the current average for a rate class.
 * <br>
 * <br>
 * The current average for a rate class is computed cumulatively. Essentially,
 * the algorithm goes like this:
 * <pre>
void computeNewAvg(long lastSent, long oldAvg,
            RateClassInfo rateClassInfo) {
    long curTime = System.currentTimeMillis();
    long diff = curTime - lastSent;

    long winSize = rateClassInfo.getWindowSize();
    long maxAvg = rateClassInfo.getMax();

    currentAvg = ((currentAvg * (winSize - 1))
            + diff) / winSize;

    if (currentAvg > maxAvg) currentAvg = maxAvg;
}
 * </pre>
 *
 * Using such an algorithm produces results almost exactly consistent with the
 * "current averages" sent in <code>RateChange</code> packets, often within a
 * margin of one or two milliseconds (out of an average of <code>5000</code> ms
 * or lower). (This margin of error is surely due to network traffic and not an
 * error in the algorithm's above implementation.)
 *
 * <h2> Being "Rate Limited" </h2>
 *
 * If commands are sent so fast as to bring the current rate average below the
 * {@linkplain #getLimitedAvg limited average}, the server will send a {@link
 * RateChange} with a {@linkplain RateChange#getChangeCode() change code} of
 * {@link RateChange#CODE_LIMITED}. After this happens, all of the commands
 * sent in the {@linkplain RateChange#getRateInfo() associated rate class} will
 * be ignored by the server until the rate reaches the {@linkplain #getClearAvg
 * "clear average"}, at which point a <code>RateChange</code> with a change code
 * of {@linkplain RateChange#CODE_LIMIT_CLEARED} <i><b>may</b></i> be sent
 * (though it is not usually sent). Once the average is above the clear average,
 * however, all is back to normal, as if limiting had never taken place.
 */
public class RateClassInfo implements Writable {
    /** The size of a rate class information block. */
    private static final int RATECLASSINFO_SIZE = 35;

    /** The rate class ID of this rate class information block. */
    private final int rateClass;
    /** The "window size." */
    private final long windowSize;

    /** The average below which you are "warned." */
    private final long warnAvg;
    /** The average below which you are rate-limited. */
    private final long limitedAvg;
    /** The average above which you are no longer rate-limited. */
    private final long clearAvg;
    /** The average below which you will be disconnected. */
    private final long disconnectAvg;

    /** Your current average. */
    private final long currentAvg;

    /** The maximum rate average. */
    private final long max;

    /** The last time a command was sent */
    private final long timeSinceLastCommand;

    /** The current state */
    private final int currentState;

    /** The commands in this rate class. */
    private List<CmdType> commands = null;

    /**
     * Generates a rate class information block from the given block of data.
     * The total number of bytes read can be accessed by calling the
     * <code>getTotalSize</code> method of the returned
     * <code>RateClassInfo</code>.
     *
     * @param block a block of data containing a rate information block
     * @return a rate class information object read from the given block of
     *         data
     */
    public static @Nullable RateClassInfo readRateClassInfo(ByteBlock block) {
        if (block.getLength() < RATECLASSINFO_SIZE) return null;

        return new RateClassInfo(block);
    }

    /**
     * Creates a new rate class information block from the data in the given
     * block.
     *
     * @param block the block of data containing rate class information
     */
    private RateClassInfo(ByteBlock block) {
        rateClass     = BinaryTools.getUShort(block,  0);
        windowSize    = BinaryTools.getUInt  (block,  2);
        clearAvg      = BinaryTools.getUInt  (block,  6);
        warnAvg       = BinaryTools.getUInt  (block, 10);
        limitedAvg    = BinaryTools.getUInt  (block, 14);
        disconnectAvg = BinaryTools.getUInt  (block, 18);
        currentAvg    = BinaryTools.getUInt  (block, 22);
        max           = BinaryTools.getUInt  (block, 26);
        if (block.getLength() >= 34) {
            timeSinceLastCommand = BinaryTools.getUInt  (block, 30);
            if (block.getLength() >= 35) {
                currentState  = BinaryTools.getUByte (block, 34);
            } else {
                currentState = -1;
            }
        } else {
            timeSinceLastCommand = 0;
            currentState = -1;
        }
    }

    /**
     * Sets the commands included in this rate class.
     *
     * @param commands the SNAC commands included in this rate class
     */
    synchronized void setCommands(Collection<? extends CmdType> commands) {
        this.commands = DefensiveTools.getSafeListCopy(commands, "commands");
    }

    public RateClassInfo(int rateClass, long windowSize, long clearAvg,
            long warnAvg, long limitedAvg, long disconnectAvg, long currentAvg,
            long max, long timeSinceLastCommand, int currentState) {
        DefensiveTools.checkRange(rateClass, "rateClass", 0);
        DefensiveTools.checkRange(windowSize, "windowSize", 0);
        DefensiveTools.checkRange(clearAvg, "clearAvg", 0);
        DefensiveTools.checkRange(warnAvg, "warnAvg", 0);
        DefensiveTools.checkRange(limitedAvg, "limitedAvg", 0);
        DefensiveTools.checkRange(disconnectAvg, "disconnectAvg", 0);
        DefensiveTools.checkRange(currentAvg, "currentAvg", 0);
        DefensiveTools.checkRange(max, "max", 0);
        DefensiveTools.checkRange(timeSinceLastCommand,
            "timeSinceLastCommand", -1);
        DefensiveTools.checkRange(currentState, "currentState", -1);

        this.rateClass = rateClass;
        this.windowSize = windowSize;
        this.clearAvg = clearAvg;
        this.warnAvg = warnAvg;
        this.limitedAvg = limitedAvg;
        this.disconnectAvg = disconnectAvg;
        this.currentAvg = currentAvg;
        this.max = max;
        this.timeSinceLastCommand = timeSinceLastCommand;
        this.currentState = currentState;
    }

    /**
     * Creates a new rate class information block with the given properties.
     * See {@linkplain RateClassInfo above} for details on what these mean.
     *
     * @param rateClass the rate class ID that this block describes
     * @param windowSize the "window size"
     * @param clearAvg the "not rate limited anymore" average
     * @param warnAvg the "warned" average
     * @param limitedAvg the "rate limited" average
     * @param disconnectAvg the "disconnected" average
     * @param currentAvg the current average
     * @param max the maximum rate average
     */
    public RateClassInfo(int rateClass, long windowSize, long clearAvg,
            long warnAvg, long limitedAvg, long disconnectAvg, long currentAvg,
            long max) {
        this(rateClass, windowSize, clearAvg, warnAvg, limitedAvg,
                disconnectAvg, currentAvg, max, 0, 0);
    }

    /**
     * Creates a new rate class information block with the given properties.
     * See {@linkplain RateClassInfo above} for details on what these mean.
     *
     * @param rateClass the rate class ID that this block describes
     * @param windowSize the "window size"
     * @param clearAvg the "not rate limited anymore" average
     * @param warnAvg the "warned" average
     * @param limitedAvg the "rate limited" average
     * @param disconnectAvg the "disconnected" average
     * @param currentAvg the current average
     * @param max the maximum rate average
     */
    public RateClassInfo(int rateClass, long windowSize, long clearAvg,
            long warnAvg, long limitedAvg, long disconnectAvg, long currentAvg,
            long max, Collection<? extends CmdType> cmds) {
        this(rateClass, windowSize, clearAvg, warnAvg, limitedAvg,
                disconnectAvg, currentAvg, max);
        setCommands(cmds);
    }
    public RateClassInfo(int rateClass, long windowSize, long clearAvg,
            long warnAvg, long limitedAvg, long disconnectAvg, long currentAvg,
            long max, long lastTime, int currentState,
            Collection<? extends CmdType> cmds) {
        this(rateClass, windowSize, clearAvg, warnAvg, limitedAvg,
                disconnectAvg, currentAvg, max, lastTime, currentState);
        setCommands(cmds);
    }

    /**
     * Returns the ID of the rate class that holds this rate class info.
     *
     * @return this rate class information block's rate class ID
     */
    public final int getRateClass() {
        return rateClass;
    }

    /**
     * Returns the "window size" of this rate class. See {@linkplain
     * RateClassInfo above} for more details.
     *
     * @return the rate class's window size
     */
    public final long getWindowSize() {
        return windowSize;
    }

    /**
     * Returns the rate average below which the user is "warned." See
     * {@linkplain RateClassInfo above} for more details.
     *
     * @return the "warned rate average"
     */
    public final long getWarnAvg() {
        return warnAvg;
    }

    /**
     * Returns the rate average below which the user is rate-limited. No
     * commands should be sent to the server in this rate class until the rate
     * average is above the {@linkplain #getClearAvg clear average}. See
     * {@linkplain RateClassInfo above} for more details.
     *
     * @return the rate-limited rate average
     */
    public final long getLimitedAvg() {
        return limitedAvg;
    }

    /**
     * Returns the rate average above which the user is no longer rate limited.
     * See {@linkplain RateClassInfo above} for more details.
     *
     * @return the rate class's "cleared of rate limiting" average
     */
    public final long getClearAvg() {
        return clearAvg;
    }

    /**
     * Returns the rate average below which the user will be disconnected. See
     * {@linkplain RateClassInfo above} for more details.
     *
     * @return the disconnect rate average
     */
    public final long getDisconnectAvg() {
        return disconnectAvg;
    }

    /**
     * Returns the user's current rate average in this rate class. See
     * {@linkplain RateClassInfo above} for more details.
     *
     * @return the user's current rate average.
     */
    public final long getCurrentAvg() {
        return currentAvg;
    }

    /**
     * Returns the maximum rate average for this rate class. See {@linkplain
     * RateClassInfo above} for more details.
     *
     * @return the maximum rate average in this class
     */
    public final long getMax() {
        return max;
    }

    public int getCurrentState() {
        return currentState;
    }

    /**
     * Returns the number of milliseconds that have elapsed since the server
     * recorded the last command sent in this rate class. This method returns
     * -1 if this value was not sent by the server.
     */
    public long getTimeSinceLastCommand() {
        return timeSinceLastCommand;
    }

    /**
     * Returns the commands included in this rate class, or <code>null</code>
     * if they were not sent (as in a <code>RateChange</code>).
     *
     * @return the SNAC command types included in this rate class
     */
    public synchronized final List<CmdType> getCommands() {
        return commands;
    }

    public long getWritableLength() {
        return RATECLASSINFO_SIZE;
    }

    public void write(OutputStream out) throws IOException {
        BinaryTools.writeUShort(out, rateClass);
        BinaryTools.writeUInt(out, windowSize);
        BinaryTools.writeUInt(out, clearAvg);
        BinaryTools.writeUInt(out, warnAvg);
        BinaryTools.writeUInt(out, limitedAvg);
        BinaryTools.writeUInt(out, disconnectAvg);
        BinaryTools.writeUInt(out, currentAvg);
        BinaryTools.writeUInt(out, max);
        if (timeSinceLastCommand != -1) {
          BinaryTools.writeUInt(out, timeSinceLastCommand);
          if (currentState != -1) {
            BinaryTools.writeUByte(out, currentState);
          }
        }
    }

    public synchronized String toString() {
        return "RateClassInfo for class " + rateClass +
                ", currentAvg=" + currentAvg +
                ", windowSize=" + windowSize +
                ", clearAvg=" + clearAvg +
                ", warnAvg=" + warnAvg +
                ", limitedAvg=" + limitedAvg +
                ", disconnectAvg=" + disconnectAvg +
                ", max=" + max +
                ", timeSinceLastCommand=" + timeSinceLastCommand +
                ", currentState=" + currentState +
                ", families: "
                + (commands == null ? "none" : "" + commands.size());
    }
}
