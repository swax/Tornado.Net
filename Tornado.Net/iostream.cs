using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

using Tornado.ioloop;


namespace Tornado.iostream
{
    public class IOStream
    {
        public Socket socket;
        public IOLoop io_loop;
        public int max_buffer_size;
        public int read_chunk_size;
        public object error;

        private LinkedList<byte[]> _read_buffer;
        private LinkedList<byte[]> _write_buffer;
        private int _read_buffer_size;
        private bool _write_buffer_frozen;
        private byte[] _read_delimiter;
        private Regex _read_regex;
        private int _read_bytes;
        private bool _read_until_close;
        private Action<byte[]> _read_callback;
        private Action<byte[]> _streaming_callback;
        private Action _write_callback;
        private Action _close_callback;
        private Action _connect_callback;
        private bool _connecting;
        private int _state;
        private int _pending_callbacks;
        

        public IOStream(Socket socket_, IOLoop io_loop_, int max_buffer_size_=104857600, int read_chunk_size_=4096)
        {
            socket = socket_;
            socket.Blocking = false;
            io_loop = io_loop_ ?? IOLoop.instance();
            max_buffer_size = max_buffer_size_;
            read_chunk_size = read_chunk_size_;
            error = null;
            _read_buffer = new LinkedList<byte[]>(); // collections.deque();
            _write_buffer = new LinkedList<byte[]>(); //collections.deque();
            _read_buffer_size = 0;
            _write_buffer_frozen = false;
            _read_delimiter = null;
            _read_regex = null;
            _read_bytes = 0; 
            _read_until_close = false;
            _read_callback = null;
            _streaming_callback = null;
            _write_callback = null;
            _close_callback = null;
            _connect_callback = null;
            _connecting = false;
            _state = 0;
            _pending_callbacks = 0;
        }

        public void read_until_regex(string regex, Action<byte[]> callback)
        {
            // Call callback when we read the given regex pattern.
            _set_read_callback(callback);
            _read_regex = new Regex(regex, RegexOptions.Compiled);
            _try_inline_read();
        }

        public void read_until(byte[] delimiter, Action<byte[]> callback)
        {
            // Call callback when we read the given delimiter.
            _set_read_callback(callback);
            _read_delimiter = delimiter;
            _try_inline_read();
        }

        public void read_bytes(int num_bytes, Action<byte[]> callback, Action<byte[]> streaming_callback=null)
        {
            /*Call callback when we read the given number of bytes.

            If a ``streaming_callback`` is given, it will be called with chunks
            of data as they become available, and the argument to the final
            ``callback`` will be empty.
            */
            _set_read_callback(callback);
            _read_bytes = num_bytes;
            _streaming_callback = streaming_callback; // stack_context.wrap(streaming_callback)
            _try_inline_read();
        }

        public void write(byte[] data, Action callback=null)
        {
            /*Write the given data to this stream.

            If callback is given, we call it when all of the buffered write
            data has been successfully written to the stream. If there was
            previously buffered write data and an old write callback, that
            callback is simply overwritten with this new callback.
            */
            //assert isinstance(data, bytes_type)
            _check_closed();
            // We use bool(_write_buffer) as a proxy for write_buffer_size>0,
            // so never put empty strings in the buffer.
            if (data != null && data.Length > 0)
            {
                // Break up large contiguous strings before inserting them in the
                // write buffer, so we don't have to recopy the entire thing
                // as we slice off pieces to send to the socket.
                var WRITE_BUFFER_CHUNK_SIZE = 128 * 1024;
                if (data.Length > WRITE_BUFFER_CHUNK_SIZE)
                {
                    //todo important write big chunk
                    //for i in range(0, len(data), WRITE_BUFFER_CHUNK_SIZE):
                    //    self._write_buffer.append(data[i:i + WRITE_BUFFER_CHUNK_SIZE])
                }
                else
                    _write_buffer.AddLast(data);
            }
            _write_callback = callback;// stack_context.wrap(callback)
            if (!_connecting)
            {
                _handle_write();
                if (_write_buffer.Any())
                    _add_io_state(IOLoop.WRITE);
                _maybe_add_error_listener();
            }
        }

        public void set_close_callback(Action callback)
        {
            //Call the given callback when the stream is closed."""
            _close_callback = callback; //stack_context.wrap(callback)
        }

        public void close()
        {
            // Close this stream.
            if (socket != null)
            {
                //if any(sys.exc_info()):
                //    error = sys.exc_info()[1]
                if (_read_until_close)
                {
                    var callback = _read_callback;
                    _read_callback = null;
                    _read_until_close = false;
                    var args = _consume(_read_buffer_size);
                    _run_callback(() => callback(args) );
                }
                if (_state != 0)
                {
                    io_loop.remove_handler(socket.fileno());
                    _state = 0;
                }
                socket.Close();
                socket = null;
            }
            _maybe_run_close_callback();
        }

        private void _maybe_run_close_callback()
        {
            if (socket == null && _close_callback != null && _pending_callbacks == 0)
            {
                // if there are pending callbacks, don't run the close callback
                // until they're done (see _maybe_add_error_handler)
                var cb = _close_callback;
                _close_callback = null;
                _run_callback(() => cb());
            }
        }

        public bool reading()
        {
            // Returns true if we are currently reading from the stream.

            return (_read_callback != null);
        }

        public bool writing()
        {
            // Returns true if we are currently writing to the stream.
            return _write_buffer.Any();
        }

        public bool closed()
        {
            //Returns true if the stream has been closed.
            return (socket == null);
        }

        private void _handle_events(int fd, int events)
        {
            if (socket == null)
            {
                //todo logging.warning("Got events for closed stream %d", fd)
                return;
            }
            try
            {
                if ((events & IOLoop.READ) != 0)
                    _handle_read();
                if (socket == null)
                    return;
                if ((events & IOLoop.WRITE) != 0)
                    if (_connecting)
                        _handle_connect();
                    _handle_write();
                if (socket == null)
                    return;
                if ((events & IOLoop.ERROR) != 0)
                {
                    //todo var err = socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                    //var error = socket.error(errno, os.strerror(errno));
                    // We may have queued up a user callback in _handle_read or
                    // _handle_write, so don't close the IOStream until those
                    // callbacks have had a chance to run.
                    io_loop.add_callback(close);
                    return;
                }
                var state = IOLoop.ERROR;
                if (reading())
                    state |= IOLoop.READ;
                if (writing())
                    state |= IOLoop.WRITE;
                if (state == IOLoop.ERROR)
                    state |= IOLoop.READ;
                if (state != _state)
                {
                    Debug.Assert(_state != 0, "shouldn't happen: _handle_events without _state");
                    _state = state;
                    io_loop.update_handler(socket, socket.fileno(), _state);
                }
            }
            catch(Exception ex)
            {
                //todo logging.error("Uncaught exception, closing connection.", exc_info=True)
                close();
                throw;
            }
        }

        private void _run_callback(Action callback)
        {
            Action wrapper = () =>
            {
                _pending_callbacks -= 1;
                try
                {
                    callback();
                }
                catch (Exception ex)
                {
                    //todo logging.error("Uncaught exception, closing connection.", exc_info=True)
                    // Close the socket on an uncaught exception from a user callback
                    // (It would eventually get closed when the socket object is
                    // gc'd, but we don't want to rely on gc happening before we
                    // run out of file descriptors)
                    close();
                    // Re-raise the exception so that IOLoop.handle_callback_exception
                    // can see it and log the error
                    throw;
                }
                _maybe_add_error_listener();
            };
            // We schedule callbacks to be run on the next IOLoop iteration
            // rather than running them directly for several reasons:
            // * Prevents unbounded stack growth when a callback calls an
            //   IOLoop operation that immediately runs another callback
            // * Provides a predictable execution context for e.g.
            //   non-reentrant mutexes
            // * Ensures that the try/except in wrapper() is run outside
            //   of the application's StackContexts
            //with stack_context.NullContext():
            {
                // stack_context was already captured in callback, we don't need to
                // capture it again for IOStream's wrapper.  This is especially
                // important if the callback was pre-wrapped before entry to
                // IOStream (as in HTTPConnection._header_callback), as we could
                // capture and leak the wrong context here.
                _pending_callbacks += 1;
                io_loop.add_callback(wrapper);
            }
        }

        private void _handle_read()
        {
            try
            {
                try
                {
                    // Pretend to have a pending callback so that an EOF in
                    // _read_to_buffer doesn't trigger an immediate close
                    // callback.  At the end of this method we'll either
                    // estabilsh a real pending callback via
                    // _read_from_buffer or run the close callback.
                    //
                    // We need two try statements here so that
                    // pending_callbacks is decremented before the `except`
                    // clause below (which calls `close` and does need to
                    // trigger the callback)
                    _pending_callbacks += 1;
                    while (true)
                    {
                        // Read from the socket until we get EWOULDBLOCK or equivalent.
                        // SSL sockets do some internal buffering, and if the data is
                        // sitting in the SSL object's buffer select() and friends
                        // can't see it; the only way to find out if it's there is to
                        // try to read it.
                        if (_read_to_buffer() == 0)
                            break;
                    }
                }
                finally
                {
                    _pending_callbacks -= 1;
                }
            }
            catch(Exception ex)
            {
                //todo logging.warning("error on read", exc_info=True)
                close();
                return;
            }
            if (_read_from_buffer())
                return;
            else
                _maybe_run_close_callback();
        }

        public void _set_read_callback(Action<byte[]> callback)
        {
            Debug.Assert(_read_callback == null, "Already reading");
            _read_callback = callback; // stack_context.wrap(callback);
        }

        public void _try_inline_read()
        {
            /* Attempt to complete the current read operation from buffered data.

            If the read can be completed without blocking, schedules the
            read callback on the next IOLoop iteration; otherwise starts
            listening for reads on the socket.
            */

            // See if we've already got the data from a previous read
            if (_read_from_buffer())
                return;
            _check_closed();
            try
            {
                // See comments in _handle_read about incrementing _pending_callbacks
                _pending_callbacks += 1;
                while (true)
                {
                    if (_read_to_buffer() == 0)
                        break;
                    _check_closed();
                }
            }
            finally
            {
                _pending_callbacks -= 1;
            }
            if (_read_from_buffer())
                return;
            _maybe_add_error_listener();
        }

        private byte[] _read_from_socket()
        {
            /*Attempts to read from the socket.

            Returns the data read or None if there is nothing to read.
            May be overridden in subclasses.
            */
            byte[] chunk = null;

            try
            {
                chunk = socket.recv(read_chunk_size);
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.WouldBlock || e.SocketErrorCode == SocketError.TryAgain)
                    return null;
                else
                    throw;
            }
            if (chunk == null)
            {
                close();
                return null;
            }
            return chunk;

        }

        private int _read_to_buffer()
        {
            /*Reads from the socket and appends the result to the read buffer.

            Returns the number of bytes read.  Returns 0 if there is nothing
            to read (i.e. the read returns EWOULDBLOCK or equivalent).  On
            error closes the socket and raises an exception.
            */
            byte[] chunk = null;

            try
            {
                chunk = _read_from_socket();
            }
            catch(SocketException ex)
            {
                // ssl.SSLError is a subclass of socket.error
                //todo logging.warning("Read error on %d: %s", socket.fileno(), e)
                close();
                throw;
            }
            if (chunk == null)
                return 0;
            _read_buffer.AddLast(chunk);
            _read_buffer_size += chunk.Length;
            if (_read_buffer_size >= max_buffer_size)
            {
                //todo logging.error("Reached maximum read buffer size")
                close();
                throw new IOError("Reached maximum read buffer size");
            }
            return chunk.Length;
        }

        public bool _read_from_buffer()
        {
            /* Attempts to complete the currently-pending read from the buffer.

            Returns True if the read was completed.
            */

            if (_streaming_callback != null && _read_buffer_size > 0)
            {
                var bytes_to_consume = _read_buffer_size;
                if (_read_bytes > 0)
                {
                    bytes_to_consume = Math.Min(_read_bytes, bytes_to_consume);
                    _read_bytes -= bytes_to_consume;
                }
                var args = _consume(bytes_to_consume);
                _run_callback(() => _streaming_callback(args));
            }
            if (_read_bytes != 0 && _read_buffer_size >= _read_bytes)
            {
                var num_bytes = _read_bytes;
                var callback = _read_callback;
                _read_callback = null;
                _streaming_callback = null;
                _read_bytes = 0;
                var args = _consume(num_bytes);
                _run_callback(() => callback(args));
                return true;
            }
            else if (_read_delimiter != null)
            {
                // Multi-byte delimiters (e.g. '\r\n') may straddle two
                // chunks in the read buffer, so we can't easily find them
                // without collapsing the buffer.  However, since protocols
                // using delimited reads (as opposed to reads of a known
                // length) tend to be "line" oriented, the delimiter is likely
                // to be in the first few chunks.  Merge the buffer gradually
                // since large merges are relatively expensive and get undone in
                // consume().
                if (_read_buffer.Any())
                {
                    while (true)
                    {
                        var loc = _read_buffer.at(0).find(_read_delimiter);
                        if (loc != -1)
                        {
                            var callback = _read_callback;
                            var delimiter_len = _read_delimiter.Length;
                            _read_callback = null;
                            _streaming_callback = null;
                            _read_delimiter = null;
                            var args = _consume(loc + delimiter_len);
                            _run_callback(() => callback(args) );
                            return true;
                        }
                        if (_read_buffer.Count == 1)
                            break;
                        _double_prefix(_read_buffer);
                    }
                }
            }
            else if (_read_regex != null)
            {
                if (_read_buffer.Any())
                {
                    while (true)
                    {
                        var m = _read_regex.Match(UTF8Encoding.UTF8.GetString(_read_buffer.at(0)));
                        if (m != null)
                        {
                            var callback = _read_callback;
                            _read_callback = null;
                            _streaming_callback = null;
                            _read_regex = null;
                            var args = _consume(m.Length); // _consume(m.end());
                            _run_callback(() => callback(args));
                            return true;
                        }
                        if (_read_buffer.Count == 1)
                            break;
                        _double_prefix(_read_buffer);
                    }
                }
            }
            return false;
        }

        private void _handle_connect()
        {
            var err = socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
            if (err != null)
            {
                //todo error = socket.error(err, os.strerror(err));
                // IOLoop implementations may vary: some of them return
                // an error state before the socket becomes writable, so
                // in that case a connection failure would be handled by the
                // error path in _handle_events instead of here.
                //logging.warning("Connect error on fd %d: %s", socket.fileno(), errno.errorcode[err])
                close();
                return;
            }
            if (_connect_callback != null)
            {
                var callback = _connect_callback;
                _connect_callback = null;
                _run_callback(callback);
            }
            _connecting = false;
        }

        private void _handle_write()
        {
            while (_write_buffer.Any())
            {
                try
                {
                    if (!_write_buffer_frozen)
                    {
                        // On windows, socket.send blows up if given a
                        // write buffer that's too large, instead of just
                        // returning the number of bytes it was able to
                        // process.  Therefore we must not call socket.send
                        // with more than 128KB at a time.
                        _merge_prefix(_write_buffer, 128 * 1024);
                    }
                    var num_bytes = socket.Send(_write_buffer.at(0));
                    if (num_bytes == 0)
                    {
                        // With OpenSSL, if we couldn't write the entire buffer,
                        // the very same string object must be used on the
                        // next call to send.  Therefore we suppress
                        // merging the write buffer after an incomplete send.
                        // A cleaner solution would be to set
                        // SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, but this is
                        // not yet accessible from python
                        // (http://bugs.python.org/issue8240)
                        _write_buffer_frozen = true;
                        break;
                    }
                    _write_buffer_frozen = false;
                    _merge_prefix(_write_buffer, num_bytes);
                    _write_buffer.popleft();
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.WouldBlock || ex.SocketErrorCode == SocketError.TryAgain)
                    {
                        _write_buffer_frozen = true;
                        break;
                    }
                    else
                    {
                        //todo logging.warning("Write error on %d: %s", socket.fileno(), e)
                        close();
                        return;
                    }
                }
            }
            if (_write_buffer.Count == 0 && _write_callback != null)
            {
                var callback = _write_callback;
                _write_callback = null;
                _run_callback(callback);
            }
        }

        private byte[] _consume(int loc)
        {
            if (loc == 0)
                return new byte[] { };
            _merge_prefix(_read_buffer, loc);
            _read_buffer_size -= loc;
            return _read_buffer.popleft();
        }

        private void _check_closed()
        {
            if (socket == null)
                throw new IOError("Stream is closed");
        }
        
        private void _maybe_add_error_listener()
        {
            if (_state == 0 && _pending_callbacks == 0)
            {
                if (socket == null)
                    _maybe_run_close_callback();
                else
                    _add_io_state(IOLoop.READ);
            }
        }

        private void _add_io_state(int state)
        {
            /*Adds `state` (IOLoop.{READ,WRITE} flags) to our event handler.

            Implementation notes: Reads and writes have a fast path and a
            slow path.  The fast path reads synchronously from socket
            buffers, while the slow path uses `_add_io_state` to schedule
            an IOLoop callback.  Note that in both cases, the callback is
            run asynchronously with `_run_callback`.

            To detect closed connections, we must have called
            `_add_io_state` at some point, but we want to delay this as
            much as possible so we don't have to set an `IOLoop.ERROR`
            listener that will be overwritten by the next slow-path
            operation.  As long as there are callbacks scheduled for
            fast-path ops, those callbacks may do more reads.
            If a sequence of fast-path ops do not end in a slow-path op,
            (e.g. for an @asynchronous long-poll request), we must add
            the error handler.  This is done in `_run_callback` and `write`
            (since the write callback is optional so we can have a
            fast-path write with no `_run_callback`)
            */
            if (socket == null)
                // connection has been closed, so there can be no future events
                return;
            if (_state == 0)
            {
                _state = IOLoop.ERROR | state;
                //with stack_context.NullContext():
                    io_loop.add_handler(
                        socket, socket.fileno(), _handle_events, _state);
            }
            else if ( (_state & state) != 0)
            {
                _state = _state | state;
                io_loop.update_handler(socket, socket.fileno(), _state);
            }
        }

        private void _double_prefix(LinkedList<byte[]> deque)
        {
            /* Grow by doubling, but don't split the second chunk just because the
            first one is small.
            */
            var new_len = Math.Max(deque.at(0).Length * 2,
                            deque.at(0).Length + deque.at(1).Length);
            _merge_prefix(deque, new_len);
        }

        private void _merge_prefix(LinkedList<byte[]> deque, int size)
        {
            /*Replace the first entries in a deque of strings with a single
            string of up to size bytes.

            >>> d = collections.deque(['abc', 'de', 'fghi', 'j'])
            >>> _merge_prefix(d, 5); print d
            deque(['abcde', 'fghi', 'j'])

            Strings will be split as necessary to reach the desired size.
            >>> _merge_prefix(d, 7); print d
            deque(['abcdefg', 'hi', 'j'])

            >>> _merge_prefix(d, 3); print d
            deque(['abc', 'defg', 'hi', 'j'])

            >>> _merge_prefix(d, 100); print d
            deque(['abcdefghij'])
            */
            if (deque.Count == 1 && deque.at(0).Length <= size)
                return;
            var prefix = new List<byte[]>();
            var remaining = size;
            while (deque.Any() && remaining > 0)
            {
                var chunk = deque.popleft();
                if (chunk.Length > remaining)
                {
                    var segment = new ArraySegment<byte>(chunk, remaining, chunk.Length - remaining);
                   
                    deque.AddFirst(chunk.substr(remaining)); // deque.AddFirst(chunk[remaining:]);
                    chunk = chunk.substr(0, remaining); // chunk = chunk[:remaining];
                }
                prefix.Add(chunk);
                remaining -= chunk.Length;
            }
            // This data structure normally just contains byte strings, but
            // the unittest gets messy if it doesn't use the default str() type,
            // so do the merge based on the type of data that's actually present.
            if (prefix.Count > 0)
                deque.AddFirst(ByteArrayExtensions.join(prefix.ToArray()));
            if (deque.Count == 0)
                deque.AddFirst(new byte[] {});
        }
    }
}
