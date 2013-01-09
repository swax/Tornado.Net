using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;


namespace Tornado.ioloop
{
    public class IOLoop
    {
        /*A level-triggered I/O loop.

        We use epoll (Linux) or kqueue (BSD and Mac OS X; requires python
        2.6+) if they are available, or else we fall back on select(). If
        you are implementing a system that needs to handle thousands of
        simultaneous connections, you should use a system that supports either
        epoll or queue.

        Example usage for a simple TCP server::

            import errno
            import functools
            import ioloop
            import socket

            def connection_ready(sock, fd, events):
                while True:
                    try:
                        connection, address = sock.accept()
                    except socket.error, e:
                        if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                            raise
                        return
                    connection.setblocking(0)
                    handle_connection(connection, address)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(0)
            sock.bind(("", port))
            sock.listen(128)

            io_loop = ioloop.IOLoop.instance()
            callback = functools.partial(connection_ready, sock)
            io_loop.add_handler(sock.fileno(), callback, io_loop.READ)
            io_loop.start()
        */

        // Constants from the epoll module
        public const int _EPOLLIN = 0x001;
        public const int _EPOLLPRI = 0x002;
        public const int _EPOLLOUT = 0x004;
        public const int _EPOLLERR = 0x008;
        public const int _EPOLLHUP = 0x010;
        public const int _EPOLLRDHUP = 0x2000;
        public const int _EPOLLONESHOT = (1 << 30);
        public const int _EPOLLET = (1 << 31);

        // Our events map exactly to the epoll events
        public const int NONE = 0;
        public const int READ = _EPOLLIN;
        public const int WRITE = _EPOLLOUT;

        public const int ERROR = _EPOLLERR | _EPOLLHUP;

        public List<Action> callbacks;

        private ISocketImpl _impl;
        private Dictionary<int, Action<int, int>> _handlers;
        private Dictionary<int, int> _events;
        private List<Action> _callbacks;
        private object _callback_lock;
        private SortedList<DateTime, _Timeout> _timeouts = new SortedList<DateTime, _Timeout>();
        private bool _running;
        private bool _stopped;
        private int _thread_ident;
        private object _blocking_signal_threshold;

        // Global lock for creating global IOLoop instance
        private object _instance_lock;

        public IOLoop(ISocketImpl impl=null)
        {
            _impl = impl ?? new _Select();
        
            //if hasattr(self._impl, 'fileno'):
            //    set_close_exec(self._impl.fileno())
            _handlers = new Dictionary<int, Action<int, int>>();
            _events = new Dictionary<int, int>();
            _callbacks = new List<Action>();
            _callback_lock = this;
            _timeouts = new SortedList<DateTime,_Timeout>();
            _running = false;
            _stopped = false;
            _thread_ident = 0;
            _blocking_signal_threshold = null;
            _instance_lock = this;

            // Create a pipe that we send bogus data to when we want to wake
            // the I/O loop when it is idle
            /*self._waker = Waker()
            self.add_handler(self._waker.fileno(),
                             lambda fd, events: self._waker.consume(),
                             self.READ)*/
        }

        private static IOLoop _instance;

        public static IOLoop instance()
        {
            /*Returns a global IOLoop instance.

            Most single-threaded applications have a single, global IOLoop.
            Use this method instead of passing around IOLoop instances
            throughout your code.

            A common pattern for classes that depend on IOLoops is to use
            a default argument to enable programs with multiple IOLoops
            but not require the argument for simpler applications::

                class MyClass(object):
                    def __init__(self, io_loop=None):
                        self.io_loop = io_loop or IOLoop.instance()
            */

            if(_instance == null)
                _instance = new IOLoop();

            return _instance;
        }

        public static bool initialized()
        {
            // Returns true if the singleton instance has been created.
            return _instance != null;
        }

        public void install()
        {
            /* Installs this IOloop object as the singleton instance.

            This is normally not necessary as `instance()` will create
            an IOLoop on demand, but you may want to call `install` to use
            a custom subclass of IOLoop.
            */

            Debug.Assert(!initialized());
            IOLoop._instance = this;
        }

        public void add_handler(Socket sock, int fd, Action<int, int> handler, int events)
        {
            // Registers the given handler to receive the given events for fd.

            _handlers[fd] = handler; //todo stack_context.wrap(handler);
            _impl.register(sock, fd, events | ERROR);
        }

        public void update_handler(Socket sock, int fd, int events)
        {
            // Changes the events we listen for fd.
            _impl.modify(sock, fd, events | ERROR);
        }

        public void remove_handler(int fd)
        {
            // Stop listening for events on fd.
            _handlers.Remove(fd);
            _events.Remove(fd);
            try
            {
                _impl.unregister(fd);   
            }
            catch(Exception ex)
            {
                //todo logging.debug("Error deleting fd from IOLoop");//, exc_info=True)
            }
        }

        public void start()
        {
            /* Starts the I/O loop.
            
            The loop will run until one of the I/O handlers calls stop(), which
            will make the loop stop after the current event iteration completes.
            */
           
            if(_stopped)
            {
                _stopped = false;
                return;
            }

            _thread_ident = thread.get_ident();
            _running = true;

            while(true)
            {
                double poll_timeout = 3600.0;

                // Prevent IO event starvation by delaying new callbacks
                // to the next iteration of the event loop.
                lock(_callback_lock)
                {
                    callbacks = _callbacks;
                    _callbacks = new List<Action>();
                }
                foreach(var callback in callbacks)
                    _run_callback(callback);

                if(_timeouts.Any())
                {
                    var now = DateTime.Now;
                    while(_timeouts.Any())
                    {
                        var timeout = _timeouts.First().Value;

                        if(timeout.callback == null)
                        {
                            // the timeout was cancelled
                            _timeouts.RemoveAt(0);
                        }
                        else if(timeout.deadline <= now)
                        {
                            _timeouts.RemoveAt(0);
                            _run_callback(timeout.callback);
                        }
                        else
                        {
                            var seconds = (timeout.deadline - now).Seconds;
                            poll_timeout = Math.Min(seconds, poll_timeout);
                        }
                    }
                }

                if(_callbacks.Any())
                {
                    // If any callbacks or timeouts called add_callback,
                    // we don't want to wait in poll() before we run them.
                    poll_timeout = 0.0;
                }

                if(!_running)
                    break;

                if(_blocking_signal_threshold != null)
                {
                    // clear alarm so it doesn't fire while poll is waiting for
                    // events.
                    //todo signal.setitimer(signal.ITIMER_REAL, 0, 0)
                }

                Dictionary<int, int> event_pairs = null;

                try
                {
                    event_pairs = _impl.poll(poll_timeout);
                }
                catch(Exception ex)
                {
                    //todo
                    // Depending on python version and IOLoop implementation,
                    // different exception types may be thrown and there are
                    // two ways EINTR might be signaled:
                    // * e.errno == errno.EINTR
                    // * e.args is like (errno.EINTR, 'Interrupted system call')
                    /*if (getattr(e, 'errno', None) == errno.EINTR or
                        (isinstance(getattr(e, 'args', None), tuple) and
                         len(e.args) == 2 and e.args[0] == errno.EINTR)):
                        continue
                    else:
                        raise*/
                }

                if(_blocking_signal_threshold != null)
                {
                    //todo signal.setitimer(signal.ITIMER_REAL,
                    //                 self._blocking_signal_threshold, 0)
                }

                // Pop one fd at a time from the set of pending fds and run
                // its handler. Since that handler may perform actions on
                // other file descriptors, there may be reentrant calls to
                // this IOLoop that update self._events
                _events.update(event_pairs);
                while(_events.Any())
                {
                    // fd, events = self._events.popitem()
                    var lastEvent = _events.popitem();
                    int fd = lastEvent.Key;
                    int events = lastEvent.Value;
                    
                    try
                    {
                        _handlers[fd](fd, events);
                    }
                    catch(SocketException ex) //except (OSError, IOError), e:
                    {
                     
                        if(ex.SocketErrorCode == SocketError.ConnectionAborted)  // if e.args[0] == errno.EPIPE:
                            // Happens when the client closes the connection
                            continue;
                        else
                            ;//todo logging.error("Exception in I/O handler for fd %s", fd, exc_info=True)
                    }
                    catch(Exception ex)
                    {
                        //todo logging.error("Exception in I/O handler for fd %s", fd, exc_info=True)
                    }
                }
            }
            
            // reset the stopped flag so another start/stop pair can be issued
            _stopped = false;
            if(_blocking_signal_threshold != null)
                ;//todo signal.setitimer(signal.ITIMER_REAL, 0, 0)
   
        }

        public void add_callback(Action callback)
        {
            /*Calls the given callback on the next I/O loop iteration.

            It is safe to call this method from any thread at any time.
            Note that this is the *only* method in IOLoop that makes this
            guarantee; all other interaction with the IOLoop must be done
            from that IOLoop's thread.  add_callback() may be used to transfer
            control from other threads to the IOLoop's thread.
            */
            var list_empty = true;

            lock (_callback_lock)
            {
                list_empty = !_callbacks.Any();
                _callbacks.Add(callback); //stack_context.wrap(callback));
            }

            if (list_empty && thread.get_ident() != _thread_ident)
            {
                // If we're in the IOLoop's thread, we know it's not currently
                // polling.  If we're not, and we added the first callback to an
                // empty list, we may need to wake it up (it may wake up on its
                // own, but an occasional extra wake is harmless).  Waking
                // up a polling IOLoop is relatively expensive, so we try to
                // avoid it when we can.
                //todo _waker.wake();
            }
        }

        private void _run_callback(Action callback)
        {
            try
            {
                callback();
            }
            catch (Exception ex)
            {
                handle_callback_exception(callback);
            }
        }

        private void handle_callback_exception(Action callback)
        {
            /*This method is called whenever a callback run by the IOLoop
            throws an exception.

            By default simply logs the exception as an error.  Subclasses
            may override this method to customize reporting of exceptions.

            The exception itself is not passed explicitly, but is available
            in sys.exc_info.
            */
            //todo logging.error("Exception in callback %r", callback, exc_info=True)
        }
    }

    class _Timeout
    {
        public Action callback;
        public DateTime deadline;
    }

    public interface ISocketImpl
    {
        Dictionary<int, int> poll(double timeout);

        void register(Socket sock, int fd, int events);

        void unregister(int fd);

        void modify(Socket sock, int fd, int events);
    }

    public class _Select : ISocketImpl
    {
        public List<Socket> read_fds = new List<Socket>();
        public List<Socket> write_fds = new List<Socket>();
        public List<Socket> error_fds = new List<Socket>();


        public void register(Socket sock, int fd_, int events)
        {
            Socket fd = sock;

            if (read_fds.Contains(fd) || write_fds.Contains(fd) || error_fds.Contains(fd))
                throw new IOError(string.Format("fd {0} already registered", fd));
            if ((events & IOLoop.READ) != 0)
                read_fds.Add(fd);
            if ((events & IOLoop.WRITE) != 0)
                write_fds.Add(fd);
            if ((events & IOLoop.ERROR) != 0)
            {
                error_fds.Add(fd);
                // Closed connections are reported as errors by epoll and kqueue,
                // but as zero-byte reads by select, so when errors are requested
                // we need to listen for both read and error.
                read_fds.Add(fd);
            }
        }

        public void modify(Socket sock, int fd, int events)
        {
            unregister(fd);
            register(sock, fd, events);
        }

        public void unregister(int fd)
        {
            read_fds.RemoveAll(s => s.fileno() == fd);
            write_fds.RemoveAll(s => s.fileno() == fd);
            error_fds.RemoveAll(s => s.fileno() == fd);
        }

        public Dictionary<int, int> poll(double timeout)
        {
            var readable = read_fds.ToList();
            var writeable = write_fds.ToList();
            var errors = error_fds.ToList();
          
            Socket.Select(readable, writeable, errors, (int)(timeout * 1000000)); // select in microseconds

            var events = new Dictionary<int, int>();
            foreach(var fd in readable.Select(r => r.fileno()))
                events[fd] = events.get(fd, 0) | IOLoop.READ;
            foreach (var fd in writeable.Select(w => w.fileno()))
                events[fd] = events.get(fd, 0) | IOLoop.WRITE;
            foreach (var fd in errors.Select(e => e.fileno()))
                events[fd] = events.get(fd, 0) | IOLoop.ERROR;
            return events;

        }
    }

    public class IOError :Exception
    {
        public IOError(string message)
            : base(message)
        {
        }
    }
}
