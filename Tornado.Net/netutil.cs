using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

using Tornado.ioloop;
using Tornado.iostream;


namespace Tornado.netutil
{
    public class TcpServer
    {
        /*A non-blocking, single-threaded TCP server.

        To use `TCPServer`, define a subclass which overrides the `handle_stream`
        method.

        `TCPServer` can serve SSL traffic with Python 2.6+ and OpenSSL.
        To make this server serve SSL traffic, send the ssl_options dictionary
        argument with the arguments required for the `ssl.wrap_socket` method,
        including "certfile" and "keyfile"::

           TCPServer(ssl_options={
               "certfile": os.path.join(data_dir, "mydomain.crt"),
               "keyfile": os.path.join(data_dir, "mydomain.key"),
           })

        `TCPServer` initialization follows one of three patterns:

        1. `listen`: simple single-process::

                server = TCPServer()
                server.listen(8888)
                IOLoop.instance().start()

        2. `bind`/`start`: simple multi-process::

                server = TCPServer()
                server.bind(8888)
                server.start(0)  # Forks multiple sub-processes
                IOLoop.instance().start()

           When using this interface, an `IOLoop` must *not* be passed
           to the `TCPServer` constructor.  `start` will always start
           the server on the default singleton `IOLoop`.

        3. `add_sockets`: advanced multi-process::

                sockets = bind_sockets(8888)
                tornado.process.fork_processes(0)
                server = TCPServer()
                server.add_sockets(sockets)
                IOLoop.instance().start()

           The `add_sockets` interface is more complicated, but it can be
           used with `tornado.process.fork_processes` to give you more
           flexibility in when the fork happens.  `add_sockets` can
           also be used in single-process servers if you want to create
           your listening sockets in some way other than
           `bind_sockets`.
        */

        public IOLoop io_loop;
        public object ssl_options;

        private Dictionary<int, Socket> _sockets;
        private List<Socket> _pending_sockets;
        private bool _started;


        public TcpServer(IOLoop io_loop_=null, object ssl_options_=null)
        {
            io_loop = io_loop_;
            ssl_options = ssl_options_;
            _sockets = new Dictionary<int, Socket>(); // fd -> socket object
            _pending_sockets = new List<Socket>();
            _started = false;
  
            // Verify the SSL options. Otherwise we don't get errors until clients
            // connect. This doesn't verify that the keys are legitimate, but
            // the SSL module doesn't do that until there is a connected socket
            // which seems like too much work 

            if (ssl_options != null)
            {
                //todo
                /* Only certfile is required: it can contain both keys
                if 'certfile' not in self.ssl_options:
                    raise KeyError('missing key "certfile" in ssl_options')

                if not os.path.exists(self.ssl_options['certfile']):
                    raise ValueError('certfile "%s" does not exist' %
                        self.ssl_options['certfile'])
                if ('keyfile' in self.ssl_options and
                        not os.path.exists(self.ssl_options['keyfile'])):
                    raise ValueError('keyfile "%s" does not exist' %
                        self.ssl_options['keyfile'])*/
            }
        }

        public void listen(int port, string address="")
        {
            /* Starts accepting connections on the given port.

            This method may be called more than once to listen on multiple ports.
            `listen` takes effect immediately; it is not necessary to call
            `TCPServer.start` afterwards.  It is, however, necessary to start
            the `IOLoop`.
            */

            var sockets = bind_sockets(port, address);
            add_sockets(sockets);
        }

        public void add_sockets(List<Socket> sockets)
        {
            /*Makes this server start accepting connections on the given sockets.

            The ``sockets`` parameter is a list of socket objects such as
            those returned by `bind_sockets`.
            `add_sockets` is typically used in combination with that
            method and `tornado.process.fork_processes` to provide greater
            control over the initialization of a multi-process server.
            */
            if(io_loop == null)
                io_loop = IOLoop.instance();

            foreach(var sock in sockets)
            {
                _sockets[sock.fileno()] = sock;
                add_accept_handler(sock, _handle_connection, io_loop);
            }
        }

        public virtual void handle_stream(IOStream stream, IPEndPoint address)
        {
            // Override to handle a new `IOStream` from an incoming connection.
            throw new NotImplementedException();
        }

        private void _handle_connection(Socket connection, IPEndPoint address)
        {
            //todo ssl
            /*if self.ssl_options is not None:
                assert ssl, "Python 2.6+ and OpenSSL required for SSL"
                try:
                    connection = ssl.wrap_socket(connection,
                                                 server_side=True,
                                                 do_handshake_on_connect=False,
                                                 **self.ssl_options)
                except ssl.SSLError, err:
                    if err.args[0] == ssl.SSL_ERROR_EOF:
                        return connection.close()
                    else:
                        raise
                except socket.error, err:
                    if err.args[0] == errno.ECONNABORTED:
                        return connection.close()
                    else:
                        raise*/
            
            try
            {
                IOStream stream = null;

                if(ssl_options != null)
                    ;//stream = SSLIOStream(connection, io_loop=self.io_loop)
                else
                    stream = new IOStream(connection, io_loop);
                handle_stream(stream, address);
            }
            catch(Exception ex)
            {
                logging.error("Error in connection callback", ex);
            }
        }

        public List<Socket> bind_sockets(int port, string address=null, AddressFamily family=AddressFamily.Unspecified, int backlog=128)
        {
            /* Creates listening sockets bound to the given port and address.

            Returns a list of socket objects (multiple sockets are returned if
            the given address maps to multiple IP addresses, which is most common
            for mixed IPv4 and IPv6 use).

            Address may be either an IP address or hostname.  If it's a hostname,
            the server will listen on all IP addresses associated with the
            name.  Address may be an empty string or None to listen on all
            available interfaces.  Family may be set to either socket.AF_INET
            or socket.AF_INET6 to restrict to ipv4 or ipv6 addresses, otherwise
            both will be used if available.

            The ``backlog`` argument has the same meaning as for
            ``socket.listen()``.
            */

            var sockets = new List<Socket>();
         
            if(address == "")
                address = null;
            //flags = socket.AI_PASSIVE
            //if hasattr(socket, "AI_ADDRCONFIG"):
                // AI_ADDRCONFIG ensures that we only try to bind on ipv6
                // if the system is configured for it, but the flag doesn't
                // exist on some platforms (specifically WinXP, although
                // newer versions of windows have it)
                //flags |= socket.AI_ADDRCONFIG

         
            //for res in set(socket.getaddrinfo(address, port, family, socket.SOCK_STREAM,
            //                              0, flags)):
            //foreach(var res in NetworkInterface.GetAllNetworkInterfaces())\
            
            var addresses = Dns.GetHostAddresses(Dns.GetHostName()).ToList();
            addresses.Add(new IPAddress(new byte[] { 127, 0, 0, 1 })); // need for localhost to work on windows

            foreach (var ipAddress in addresses)
            {
                //af, socktype, proto, canonname, sockaddr = res
                //sock = socket.socket(af, socktype, proto)
                var sock = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                //set_close_exec(sock.fileno())
                //if os.name != 'nt':
                //    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                //if af == socket.AF_INET6:
                    // On linux, ipv6 sockets accept ipv4 too by default,
                    // but this makes it impossible to bind to both
                    // 0.0.0.0 in ipv4 and :: in ipv6.  On other systems,
                    // separate sockets *must* be used to listen for both ipv4
                    // and ipv6.  For consistency, always disable ipv4 on our
                    // ipv6 sockets and use a separate ipv4 socket when needed.
                    //
                    // Python 2.x on windows doesn't have IPPROTO_IPV6.
                    //if hasattr(socket, "IPPROTO_IPV6"):
                    //    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

                sock.Blocking = false;
                sock.Bind(new IPEndPoint(ipAddress, port)); 
                sock.Listen(backlog);
                sockets.Add(sock);
            }

            return sockets;
        }

        public void add_accept_handler(Socket sock, Action<Socket, IPEndPoint> callback, IOLoop io_loop = null)
        {
            /*Adds an ``IOLoop`` event handler to accept new connections on ``sock``.

            When a connection is accepted, ``callback(connection, address)`` will
            be run (``connection`` is a socket object, and ``address`` is the
            address of the other end of the connection).  Note that this signature
            is different from the ``callback(fd, events)`` signature used for
            ``IOLoop`` handlers.
            */

            if (io_loop == null)
                io_loop = IOLoop.instance();

            Action<int, int> accept_handler = (fd, events) =>
            {
                while (true)
                {
                    Socket connection = null;

                    try
                    {
                        connection = sock.Accept();
                    }
                    catch (SocketException ex)
                    {
                        if (ex.SocketErrorCode == SocketError.WouldBlock || ex.SocketErrorCode == SocketError.TryAgain)
                            return;

                        throw;
                    }

                    callback(connection, connection.RemoteEndPoint as IPEndPoint);
                }
            };

            io_loop.add_handler(sock, sock.fileno(), accept_handler, IOLoop.READ);
        }
    }
}