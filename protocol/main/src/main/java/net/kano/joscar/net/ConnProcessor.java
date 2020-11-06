/*
 *  Copyright (c) 2006, The Joust Project
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
 */

package net.kano.joscar.net;

import net.kano.joscar.common.DefensiveTools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public interface ConnProcessor {
    /**
     * Attaches this connection processor to the given socket's input and output
     * streams. Behavior is undefined if the given socket is not connected (that
     * just means an <code>IOException</code> will probably be thrown).
     * <br>
     * <br>
     * Note that this does not begin any sort of loop or connection; it only
     * sets the values of the input and output streams.
     *
     * @param socket the socket to attach to
     * @throws IOException if an I/O error occurs
     */
    void attachToSocket(Socket socket) throws IOException;

    /**
     * Attaches this connection processor to the given input stream. This stream
     * is from whence packets will be read. Note that <code>in</code> cannot be
     * <code>null</code>; to detach from a stream, use {@link #detach}.
     *
     * @param in the input stream to attach to
     */
    void attachToInput(InputStream in);

    /**
     * Attaches this connection processor to the given output stream. This
     * stream is where packets sent via the <code>send</code> method will be
     * written. Note that <code>out</code> cannot be <code>null</code>; to
     * detach from a stream, use {@link #detach}.
     *
     * @param out the output stream to attach to
     */
    void attachToOutput(OutputStream out);

    /**
     * Detaches this connection processor from any attached input and/or output
     * stream.
     */
    void detach();

    /**
     * Adds an exception handler for connection-related exceptions.
     *
     * @param handler the handler to add
     */
    void addExceptionHandler(
            ConnProcessorExceptionHandler handler);

    /**
     * Removes an exception handler from this processor.
     *
     * @param handler the handler to remove
     */
    void removeExceptionHandler(
            ConnProcessorExceptionHandler handler);

    /**
     * Processes the given exception with the given error type. This exception
     * will be passed to all registered exception handlers. Calling this method
     * is equivalent to calling {@link
     * #handleException(ConnProcessor.ErrorType, Throwable, Object) handleException(type,
     * t, null)}.
     *
     * @param type an object representing the type or source of the given
     *        exception
     * @param t the exception that was thrown
     *
     * @see #addExceptionHandler
     */
    void handleException(ErrorType type, Throwable t);

    /**
     * Processes the given exception with the given error type and error detail
     * info. This exception will be passed to all registered exception handlers.
     *
     * @param type an object representing the type or source of the given
     *        exception
     * @param t the exception that was thrown
     * @param info an object containing extra information or details on this
     *        exception and/or what caused it
     */
    void handleException(ErrorType type, Throwable t, Object info);

    /**
     * An enumeration class for connection processor error types.
     */
    static final class ErrorType {
        /** The name of this error type. */
        private final String name;

        /**
         * Creates a new error type object with the given name.
         *
         * @param name the name of this error type
         */
        public ErrorType(String name) {
            DefensiveTools.checkNull(name, "name");

            this.name = name;
        }

        public String toString() {
            return name;
        }
    }
}
