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

package net.kano.joscar;

import java.nio.charset.StandardCharsets;
import net.kano.joscar.common.BinaryTools;
import net.kano.joscar.common.ByteBlock;
import net.kano.joscar.common.DefensiveTools;
import net.kano.joscar.common.StringBlock;
import net.kano.joscar.logging.Logger;
import net.kano.joscar.logging.LoggingSystem;
import net.kano.joscar.snaccmd.MiniRoomInfo;
import net.kano.joustsim.Screenname;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides a set of tools for performing OSCAR-specific functions.
 */
public final class OscarTools {
    /** A logger for errors caused in the methods this class. */
    private static final Logger logger = LoggingSystem.getLogger("net.kano.joscar");

    /** A regular expression that only matches valid names for charsets. */
    private static final Pattern charsetPattern
            = Pattern.compile("[A-Za-z0-9][A-Za-z0-9-.:_]*");

    /**
     * A regular expression for processing AIM info content type strings. See
     * {@link #parseContentTypeString parseContentTypeString} for details.
     */
    private static final Pattern typePattern = Pattern.compile(
        "[;=\\s]*+" + // any leading semicolons, equals signs, and space
            "(\\S+?)" + // the key name, without spaces (like "charset")
            "\\s*" + // any whitespace after the key name
            "(?:=\\s*" + // an equals sign, followed by possible whitespace
            "(?:" +
            "\"(.*?)\"" + // a value after the equals sign, in quotes
            "|(\\S*?)" + // a single-word value not in quotes
            ")" +
            "\\s*" + // any more whitespace after the value
            ")?" +
            "(?:" +
            "[=\\s]*;[=\\s]*" + // a semicolon surrounded by whitespace or
            // stray equals signs
            "|\\z" + // or the end of the input
            ")");

    /** A regular expression that matches the name of a UCS-2 charset. */
    private static final Pattern ucsPattern = Pattern.compile("ucs-2([bl]e)?");

    private static String defaultCharset = null;
    private static Charset defaultCharsetObject = null;
    private static final Object defaultCharsetLock = new Object();

    static {
        resetDefaultCharset();
    }

    /**
     * A private constructor that is never called ensures that this class cannot
     * be instantiated.
     */
    private OscarTools() { }

    /**
     * Reads a screenname which is preceded by a single byte describing the
     * screenname's length from the given block of data. Returns
     * <code>null</code> if no such valid object can be read.
     *
     * @param data the block containing a single-byte length followed by a
     *        screen name in US-ASCII format
     * @return an object containing the screenname and the total number of bytes
     *         read, or <code>null</code>
     */
    public static @Nullable StringBlock readScreenname(ByteBlock data) {
        if (data.getLength() < 1) return null;

        int length = BinaryTools.getUByte(data, 0);

        if (length > data.getLength() - 1) return null;

        String sn = BinaryTools.getAsciiString(data.subBlock(1, length));

        return new StringBlock(sn, length + 1);
    }

    /**
     * Writes the given screenname to the given stream, preceded by a single
     * byte containing the screenname's length in bytes.
     *
     * @param out the stream to write to
     * @param sn the screenname to write to the given stream
     * @throws IOException if an I/O error occurs
     */
    public static void writeScreenname(OutputStream out, String sn)
            throws IOException {
        byte[] bytes = BinaryTools.getAsciiBytes(sn);

        BinaryTools.writeUByte(out, bytes.length);
        out.write(bytes);
    }

    /**
     * Converts a string like <code>text/x-aolrtf;
     * charset=us-ascii</code> to a <code>Map</code> with two keys:
     * <code>text/x-aolrtf</code> (value <code>null</code>) and
     * <code>charset</code> (value <code>us-ascii</code>).
     *
     * @param  str the content type string
     * @return     a map with keys and values extracted from the given string
     */
    public static Map<String,String> parseContentTypeString(String str) {
        // create a fun matcher
        Matcher matcher = typePattern.matcher(str);

        // and a map to store keys/values in
        Map<String,String> entries = new HashMap<String, String>();

        // and get all the matches..
        while (matcher.find()) {
            // the first group is \S+?, or the first nonwhitespace string before
            // an equals sign or a semicolon or the end of the string. so "key"
            // in "key=value;"
            String key = matcher.group(1);

            // the second group is .*?, or anything inside quotes. note that
            // this does not allow for anything like backslashed quotes.
            String value = matcher.group(2);

            if (value == null) {
                // there was no quoted value, so look for an unquoted value.
                // if this is null we don't care, because it means they're both
                // null and there's no value for this key.
                value = matcher.group(3);
            }

            // and put the key & value into the map!
            entries.put(key, value);
        }

        return entries;
    }

    /**
     * Returns <code>true</code> if the given charset name is a valid charset
     * name. Note that this method does not check to see whether the given
     * charset is available; rather it just checks that the name is in the
     * correct format.
     *
     * @param charset the name of the charset to check
     * @return whether the given charset is in a valid charset name format
     */
    private static boolean isValidCharset(String charset) {
        return charsetPattern.matcher(charset).matches();
    }

    /**
     * Sets the default charset to ISO8859-1 if available, otherwise to US-ASCII
     * (which is guaranteed on all JVM's).
     */
    public static void resetDefaultCharset() {
        defaultCharset = StandardCharsets.ISO_8859_1.name();
        defaultCharsetObject = StandardCharsets.ISO_8859_1;
    }

    /**
     * Sets a private static <code>defaultCharset</code> value that
     * can be accessed by {@link #getDefaultCharsetName getDefaultCharsetName}
     *
     * @throws IllegalArgumentException if the charset is not available
     */
    public static void setDefaultCharset(String charset)
            throws IllegalArgumentException {
        if (isValidCharset(charset)) {
            if (Charset.isSupported(charset)) {
                synchronized (defaultCharsetLock) {
                    defaultCharset = charset;
                    // reset charset object for lazy initialization
                    defaultCharsetObject = null;
                }
            } else {
                throw new IllegalArgumentException(
                        "Unsupported charset: " + charset);
            }
        } else {
            throw new IllegalArgumentException(
                    "Invalid charset name: " + charset);
        }
    }

    /**
     * Sets a private static <code>defaultCharset</code> value that
     * can be accessed by {@link #getDefaultCharsetName getDefaultCharsetName}
     */
    public static void setDefaultCharset(Charset charset) {
        synchronized (defaultCharsetLock) {
            defaultCharset = charset.name();
            defaultCharsetObject = charset;
        }
    }

    /**
     * Returns a name of the default charset. Returns a
     * <code>defaultCharset</code> value if it was
     * set and accepted by setDefaultCharset(), or ISO8859-1 (if supported),
     * or US-ASCII after all.
     */
    public static String getDefaultCharsetName() {
        synchronized (defaultCharsetLock) {
            return defaultCharset;
        }
    }

    /**
     * Returns the charset identified by {@link #getDefaultCharsetName()}
     */
    public static Charset getDefaultCharset() {
        synchronized (defaultCharsetLock) {
          Charset object = defaultCharsetObject;
          if (object != null) {
              return object;
          }
          Charset newCharset = Charset.forName(defaultCharset);
          defaultCharsetObject = newCharset;
          return newCharset;
        }
    }

    /**
     * Returns a valid, hopefully compatible charset name from the given charset
     * name. For example, attempts to convert such names as "unicode-2.0" to
     * "UTF-16BE". The returned charset name is guaranteed to be supported by
     * the JVM; that is, the returned charset can always be used to encode
     * without further processing. This method falls back to the
     * {@linkplain #getDefaultCharsetName() default charset} if no charset can be
     * deciphered from {@code charset}.
     *
     * @param charset the possibly invalid charset, or <code>null</code>
     * @return a valid charset derived from the given charset name
     */
    private static String fixCharset(String charset) {
        if (charset == null) return getDefaultCharsetName();

        // sigh. ok, first attempt to hax0r unicode 2.0, since java doesn't
        // support it yet, and iChat, well, does.
        String lower = charset.toLowerCase();
        if (lower.equals("unicode-2-0")) {
            // we think unicode-2.0's default encoding might just be UTF-16.
            return "UTF-16BE";
        }
        if (lower.startsWith("unicode-2-0-")) {
            // the charset is "unicode-2-0-SOMECHARSET", so let's extract
            // SOMECHARSET and hope it works
            String newCharset = charset.substring(12);

            if (isValidCharset(newCharset) && Charset.isSupported(newCharset)) {
                // this is a valid charset!
                return newCharset;
            }
        }

        // okay, none of those was true. check for UCS-2, which is just UTF-16
        Matcher matcher = ucsPattern.matcher(charset);
        if (matcher.matches()) {
            // it's UCS-2! get the type, LE or BE (or null if neither)
            String type = matcher.group(1);

            // and build the corresponding UTF-16 type
            String newCharset = "utf-16";
            if (type != null) newCharset += type;

            // and return it
            return newCharset;
        }

        // okay. none of those worked. let's use the default one. :/
        return getDefaultCharsetName();
    }

    /**
     * Returns a string given its binary representation and one of AIM's
     * <code>text/x-aolrtf; charset=us-ascii</code> content-type strings. This
     * method falls back on the
     * {@linkplain #getDefaultCharsetName() default charset} if it cannot figure out
     * which charset was intended by the sender.
     *
     * @param infoData the binary representation of the string
     * @param infoType an AIM content-type string
     * @return a string decoded from the given byte block and the charset
     *         that might be specified in the given content-type string
     */
    public static String getInfoString(ByteBlock infoData, String infoType) {
        // declare this up here
        String charset;

        if (infoType != null) {
            // get a content type map
            Map<String,String> type = parseContentTypeString(infoType);

            // extract the charset, if there is one
            charset = type.get("charset");

            charset = getValidCharset(charset);
        } else {
            // there's no encoding given! so just use the default.
            charset = getDefaultCharsetName();
        }

        try {
            // okay, finally, decode the data
            return ByteBlock.createString(infoData, charset);
        } catch (UnsupportedEncodingException impossible) { return null; }
    }

    /**
     * Returns the given charset if it is supported by the JVM; if it is not
     * supported, attempts to fix it and returns the "fixed" version. This
     * method will always return the name of a charset that can be used within
     * this JVM. Note that if <code>charset</code> is <code>null</code>,
     * <code>StandardCharsets.US_ASCII</code> will be returned.
     *
     * @param charset the charset name to "fix"
     * @return either the given charset name or a valid charset name derived
     *         from the given name
     */
    public static String getValidCharset(String charset) {
        // use defaultCharset if there's no charset or if the name isn't a valid
        // charset name according to the isSupported javadoc (if there's a
        // method like isValidCharsetName(), please someone email me, but
        // I'm pretty sure there isn't)
        String goodCharset = charset;

        if (goodCharset == null || !isValidCharset(goodCharset)) {
            goodCharset = fixCharset(goodCharset);
        } else {
            try {
                if (!Charset.isSupported(goodCharset)) {
                    // if this character set isn't supported, try some other
                    // stuff
                    goodCharset = fixCharset(goodCharset);
                }
            } catch (IllegalCharsetNameException e) {
                // this shouldn't happen, so be very loud and angry about it
                logger.logWarning("Illegal charset name: " + goodCharset + ": "
                        + e.getMessage());

                // and default after all
                goodCharset = fixCharset(goodCharset);
            }
        }
        return goodCharset;
    }

    /**
     * Creates a <code>String</code> from the given block of data and the given
     * charset. Note that this will <i>never</i> return <code>null</code>, even
     * if the given <code>charset</code> is <code>null</code>. This method will
     * do its best to produce a <code>String</code> from the given data using
     * {@link #getValidCharset getValidCharset}.
     *
     * @param data a block of data containing a string
     * @param charset the name of a charset to use to extract a string from the
     *        given data, or <code>null</code> for US-ASCII
     * @return a <code>String</code> decoded from the given block of data
     */
    public static String getString(ByteBlock data, String charset) {
        String realCharset = getValidCharset(charset);

        try {
            return ByteBlock.createString(data, realCharset);
        } catch (UnsupportedEncodingException impossible) { return null; }
    }

    /**
     * Creates a <code>String</code> from the given block of data and the given
     * charset. Note that this will <i>never</i> return <code>null</code>, even
     * if the given <code>charset</code> is <code>null</code>. This method will
     * do its best to produce a <code>String</code> from the given data using
     * {@link #getValidCharset getValidCharset}.
     *
     * @param data a block of data containing a string
     * @param charset the name of a charset to use to extract a string from the
     *        given data, or <code>null</code> for US-ASCII
     * @return a <code>String</code> decoded from the given block of data
     */
    public static String getString(ByteBlock data, Charset charset) {
        if (charset == null) {
            charset = StandardCharsets.US_ASCII;
        }
        return ByteBlock.createString(data, charset);
    }

  /**
     * Returns whether the given strings are equal when compared as screennames.
     * For details, see {@link net.kano.joustsim.Screenname#normalize}.
     * <br><br>
     * For example, <code>equalScreennames("Joustacular", "j o ust
     * acular")</code> will return <code>true</code>.
     *
     * @param a a screenname
     * @param b a screenname
     * @return whether the two screennames are equal
     */
    public static boolean equalScreennames(String a, String b) {
        DefensiveTools.checkNull(a, "a");
        DefensiveTools.checkNull(b, "b");

        return Screenname.normalize(a).equals(Screenname.normalize(b));
    }

    /** A poor regular expression to match an HTML tag. */
    private static final Pattern htmlRE = Pattern.compile("<[^>]*>");

    /**
     * Uses a poorly conceived method to remove HTML from a string. "Not for
     * production use."
     *
     * @param str the string from which to strip HTML tags
     * @return the given string with HTML tags removed
     */
    public static String stripHtml(String str) {
        return htmlRE.matcher(str).replaceAll("");
    }

    /**
     * A regular expression matching complete lines containing a single HTTP
     * header. A newline sequence (<code>\r\n|\r|\n</code>) at the end of the
     * line is matched as well.
     */
    private static final Pattern httpHeaderRE
            = Pattern.compile("((.*?)(?:: ?(.*))?)(\r\n|\r|\n)");

    /**
     * Extracts HTTP header information and the block of data being sent in the
     * HTTP stream from a block of binary data. The header is presumed to be in
     * US-ASCII encoding (that is, all characters are a single byte), but the
     * data after the header can be in any format; it is not parsed, only
     * returned. One should note that all three popular newline formats are
     * supported in parsing the header: <code>\r</code>, <code>\n</code>,
     * and <code>\r\n</code>.
     * <br>
     * <br>
     * An example:<br>
     * <dl>
     * <dt>Input:</dt>
     * <dd><pre style="background: #cccccc; color: black; border: 2px solid black">
Content-Type: text/x-aolrtf
Content-Encoding: binary

&lt;HTML&gt;I am a banana&lt;/HTML&gt;
</pre></dd>
     * <dt>Sample code:</dt>
     * <dd><pre style="background: #cccccc; color: black; border: 2px solid black">
ByteBlock input = ...;
OscarTools.HttpHeaderInfo hinfo
        = OscarTools.parseHttpHeader(input);
System.out.println("Content type of input is "
        + hinfo.get("content-type"));
     System.out.println("Content encoding of input is "
     + hinfo.get("Content-Encoding"));
System.out.println("message text is "
        + ByteBlock.createString(hinfo.getData(),
        StandardCharsets.US_ASCII);
     </pre></dd>
     * </dl>
     *
     * Something important to note is that the header names in the returned
     * structure are also present in lowercase form. (This is so mainly for
     * convenience.)
     *
     * @param data the block of data containing an HTTP header followed by data
     * @return a structure containing HTTP header information and the data
     *         following the headers for the given input
     */
    public static HttpHeaderInfo parseHttpHeader(ByteBlock data) {
        DefensiveTools.checkNull(data, "data");

        Map<String,String> map = new HashMap<String, String>();

        DynAsciiCharSequence seq = new DynAsciiCharSequence(data);
        Matcher m = httpHeaderRE.matcher(seq);
        int dataStart = -1;
        while (true) {
            // skip to the next match
            if (!m.find()) break;

            if (m.group(1).trim().length() == 0) {
                dataStart = m.end();
                break;
            }

            String key = m.group(2);
            String val = m.group(3);
            map.put(key.toLowerCase(), val);
            map.put(key, val);
        }

        return new HttpHeaderInfo(map,
                dataStart == -1 ? null : data.subBlock(dataStart));
    }

    /**
     * A structure containing HTTP header information along with the binary data
     * sent in the HTTP stream.
     */
    public static final class HttpHeaderInfo {
        /** The header information. */
        private final Map<String,String> headers;
        /** The data sent in the HTTP stream. */
        private final ByteBlock data;

        /**
         * Creates a new HTTP header information object with the given header
         * information and data block.
         *
         * @param headers the HTTP header information
         * @param data the block of data sent in the HTTP stream
         */
        private HttpHeaderInfo(Map<String,String> headers, ByteBlock data) {
            DefensiveTools.checkNull(headers, "headers");
            DefensiveTools.checkNull(data, "data");

            this.headers = Collections.unmodifiableMap(headers);
            this.data = data;
        }

        /**
         * Returns the value of the header with the given name.
         *
         * @param headerName the name of the header to retrieve, like
         *        "content-type"
         * @return the value of the given header, or <code>null</code> if the
         *         given header was not sent in the associated HTTP stream
         */
        public String get(String headerName) {
            return headers.get(headerName);
        }

        /**
         * Returns an immutable <code>Map</code> that contains the HTTP header
         * names as keys and the associated header values as values. See
         * {@link OscarTools#parseHttpHeader(ByteBlock)} for details.
         *
         * @return a map from HTTP header names to their values
         */
        public Map<String,String> getHeaders() { return headers; }

        /**
         * Returns the block of data sent in the associated HTTP stream.
         *
         * @return the block of data sent after the headers in the HTTP stream
         *         from which this object was created
         */
        public ByteBlock getData() { return data; }

        public String toString() {
            return "HttpHeaderInfo: headers=" + headers;
        }
    }

    /**
     * A regular expression that matches the "cookie" or "URL" of a chat room.
     */
    private static final Pattern roomNameRE
            = Pattern.compile("!aol://\\d+:\\d+-\\d+-(.*)");

    /**
     * Returns the name of the chat room described by the given "cookie" or
     * "chat room URL." See {@link MiniRoomInfo#getCookie()} for details.
     * For example, with the input <code>"!aol://2719:11-4-room%20name"</code>,
     * this method will return <code>"room name"</code>.
     *
     * @param cookie a chat room "cookie"
     * @return the name of the chat room described by the cookie
     */
    public static @Nullable String getRoomNameFromCookie(String cookie) {
        Matcher m = roomNameRE.matcher(cookie);
        if (!m.matches()) return null;

        String encodedName = m.group(1);

        String name = null;
        try {
            name = URLDecoder.decode(encodedName, "us-ascii");
        } catch (UnsupportedEncodingException impossible) { }

        return name;
    }
}
