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
 *  File created by keith @ Feb 18, 2003
 *
 */

package net.kano.joscar.tlv;

import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.OscarTools;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * A base class for TLV chains, implementing basic functionality while leaving
 * extra features and data storage to subclasses.
 * <br>
 * <br>Extending this class requires one to hold both a list of all contained
 * TLV's as well as a map from TLV type to TLV's in the chain with that type.
 * See {@link #getTlvList} and {@link #getTlvMap} for details.
 */
public abstract class AbstractTlvChain implements TlvChain {
    /** The total size of this chain, as read from an incoming stream. */
    private int totalSize;

    /**
     * Creates a new TLV chain with a total size of <code>-1</code>.
     */
    protected AbstractTlvChain() {
        this(-1);
    }

    /**
     * Creates a new TLV chain with the given total byte size, as read from an
     * incoming stream.
     *
     * @param totalSize the total size of this object, in bytes, or
     *        <code>-1</code> if this object was not read from a block of binary
     *        data
     */
    protected AbstractTlvChain(int totalSize) {
        DefensiveTools.checkRange(totalSize, "totalSize", -1);

        this.totalSize = totalSize;
    }

    /**
     * Effectively makes this chain a copy of the given chain.
     *
     * @param chain a TLV chain to copy
     */
    protected synchronized final void copy(TlvChain chain) {
        DefensiveTools.checkNull(chain, "chain");

        totalSize = getTotalSize();

        List<Tlv> tlvList = getTlvList();
        Map<Integer,List<Tlv>> tlvMap = getTlvMap();

        tlvList.clear();
        tlvMap.clear();

        if (chain instanceof AbstractTlvChain) {
            // this is easy
            AbstractTlvChain atc = (AbstractTlvChain) chain;

            tlvList.addAll(atc.getTlvList());
            tlvMap.putAll(atc.getTlvMap());
        } else {
            // this is messier and a bit slower
            for (Tlv tlv : chain.getTlvs()) addTlvImpl(tlv);
        }
    }

    /**
     * Copies the given number of TLV's from the given block of TLV's into this
     * chain.
     *
     * @param block a data block containing zero or more TLV's
     * @param maxTlvs the maximum number of TLV's to read, or <code>-1</code> to
     *        read all possible TLV's in the given block
     */
    protected final synchronized void initFromBlock(ByteBlock block,
            int maxTlvs) {
        DefensiveTools.checkNull(block, "block");
        DefensiveTools.checkRange(maxTlvs, "maxTlvs", -1);

        ByteBlock next = block;
        int start = next.getOffset();
        for (int i = 0;
             Tlv.isValidTLV(next) && (maxTlvs == -1 || i < maxTlvs);
             i++) {
            Tlv tlv = new Tlv(next);

            addTlvImpl(tlv);

            next = next.subBlock(tlv.getTotalSize());
        }

        totalSize = next.getOffset() - start;
    }

    /**
     * Adds a TLV to this chain. Presumably for use by mutable subclasses.
     *
     * @param tlv a TLV to add to this chain
     */
    protected void addTlvImpl(Tlv tlv) {
        DefensiveTools.checkNull(tlv, "tlv");

        getTlvList().add(tlv);

        Integer type = tlv.getType();
        List<Tlv> siblings = getTlvMap().get(type);

        if (siblings == null) {
            siblings = createSiblingList();
            getTlvMap().put(type, siblings);
        }

        siblings.add(tlv);
    }

    public boolean hasTlv(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        return getTlvMap().containsKey(type);
    }

    public List<Tlv> getTlvs() {
        return DefensiveTools.getUnmodifiableCopy(getTlvList());
    }

    public Iterator<Tlv> iterator() {
        return getTlvs().iterator();
    }

    public int getTlvCount() {
        return getTlvList().size();
    }

    public Tlv getFirstTlv(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        List<Tlv> list = getTlvMap().get(type);
        return list == null ? null : list.get(0);
    }

    public Tlv getLastTlv(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        List<Tlv> list = getTlvMap().get(type);
        return list == null ? null : list.get(list.size() - 1);
    }

    public List<Tlv> getTlvs(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        List<Tlv> list = getTlvMap().get(type);
        if (list == null) {
            return DefensiveTools.emptyList();
        }
        else {
            return DefensiveTools.getUnmodifiableCopy(list);
        }
    }

    public String getString(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        return hasTlv(type) ? getLastTlv(type).getDataAsString() : null;
    }

    public String getUtf8String(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        return hasTlv(type) ? getLastTlv(type).getDataAsUtf8() : null;
    }

    public @Nullable String getString(int type, @Nullable String charset) {
        DefensiveTools.checkRange(type, "type", 0);

        if (!hasTlv(type)) return null;

        ByteBlock stringBlock = getLastTlv(type).getData();
        return OscarTools.getString(stringBlock, charset);
    }

    public int getUShort(int type) {
        DefensiveTools.checkRange(type, "type", 0);

        return hasTlv(type) ? getLastTlv(type).getDataAsUShort() : -1;
    }

    public long getUInt(int type) {
        Tlv tlv = getFirstTlv(type);

        if (tlv == null) return -1;
        return tlv.getDataAsUInt();
    }

    public synchronized int getTotalSize() {
        return totalSize;
    }

    public long getWritableLength() {
        int sum = 0;
        for (Tlv tlv : getTlvList()) {
            sum += (tlv).getWritableLength();
        }
        return sum;
    }

    public void write(OutputStream out) throws IOException {
        for (Tlv tlv : getTlvList()) {
            tlv.write(out);
        }
    }

    /**
     * Returns a list of all of the TLV's in this chain.
     *
     * @return a list containing each of the TLV's in this chain, in order
     */
    protected abstract List<Tlv> getTlvList();

    /**
     * Returns a map from TLV types (as <code>Integer</code>s) to TLV lists (as
     * <code>List</code>s). The list should contain all TLV's of the given TLV
     * type that exist in this TLV chain, in the same order as they appear in
     * the full list.
     *
     * @return a map from TLV type to
     */
    protected abstract Map<Integer,List<Tlv>> getTlvMap();

    /**
     * Creates a new <code>List</code> to serve as a value for the {@linkplain
     * #getTlvMap TLV map}. The default implementation returns a
     * <code>LinkedList</code>.
     *
     * @return an empty list that can be used to store TLV's in this chain's TLV
     *         map
     */
    protected List<Tlv> createSiblingList() {
        return new LinkedList<Tlv>();
    }

    public String toString() {
        return getTlvList().toString();
    }
}
