using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Tornado.httputil;
using Tornado.ioloop;
using Tornado.iostream;
using Tornado.netutil;


namespace Tornado.httpserver
{
    public class HTTPServer : TcpServer
    {
        /*"""A non-blocking, single-threaded HTTP server.

        A server is defined by a request callback that takes an HTTPRequest
        instance as an argument and writes a valid HTTP response with
        `HTTPRequest.write`. `HTTPRequest.finish` finishes the request (but does
        not necessarily close the connection in the case of HTTP/1.1 keep-alive
        requests). A simple example server that echoes back the URI you
        requested::

            import httpserver
            import ioloop

            def handle_request(request):
               message = "You requested %s\n" % request.uri
               request.write("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (
                             len(message), message))
               request.finish()

            http_server = httpserver.HTTPServer(handle_request)
            http_server.listen(8888)
            ioloop.IOLoop.instance().start()

        `HTTPServer` is a very basic connection handler. Beyond parsing the
        HTTP request body and headers, the only HTTP semantics implemented
        in `HTTPServer` is HTTP/1.1 keep-alive connections. We do not, however,
        implement chunked encoding, so the request callback must provide a
        ``Content-Length`` header or implement chunked encoding for HTTP/1.1
        requests for the server to run correctly for HTTP/1.1 clients. If
        the request handler is unable to do this, you can provide the
        ``no_keep_alive`` argument to the `HTTPServer` constructor, which will
        ensure the connection is closed on every request no matter what HTTP
        version the client is using.

        If ``xheaders`` is ``True``, we support the ``X-Real-Ip`` and ``X-Scheme``
        headers, which override the remote IP and HTTP scheme for all requests.
        These headers are useful when running Tornado behind a reverse proxy or
        load balancer.

        `HTTPServer` can serve SSL traffic with Python 2.6+ and OpenSSL.
        To make this server serve SSL traffic, send the ssl_options dictionary
        argument with the arguments required for the `ssl.wrap_socket` method,
        including "certfile" and "keyfile"::

           HTTPServer(applicaton, ssl_options={
               "certfile": os.path.join(data_dir, "mydomain.crt"),
               "keyfile": os.path.join(data_dir, "mydomain.key"),
           })

        `HTTPServer` initialization follows one of three patterns (the
        initialization methods are defined on `tornado.netutil.TCPServer`):

        1. `~tornado.netutil.TCPServer.listen`: simple single-process::

                server = HTTPServer(app)
                server.listen(8888)
                IOLoop.instance().start()

           In many cases, `tornado.web.Application.listen` can be used to avoid
           the need to explicitly create the `HTTPServer`.

        2. `~tornado.netutil.TCPServer.bind`/`~tornado.netutil.TCPServer.start`:
           simple multi-process::

                server = HTTPServer(app)
                server.bind(8888)
                server.start(0)  # Forks multiple sub-processes
                IOLoop.instance().start()

           When using this interface, an `IOLoop` must *not* be passed
           to the `HTTPServer` constructor.  `start` will always start
           the server on the default singleton `IOLoop`.

        3. `~tornado.netutil.TCPServer.add_sockets`: advanced multi-process::

                sockets = tornado.netutil.bind_sockets(8888)
                tornado.process.fork_processes(0)
                server = HTTPServer(app)
                server.add_sockets(sockets)
                IOLoop.instance().start()

           The `add_sockets` interface is more complicated, but it can be
           used with `tornado.process.fork_processes` to give you more
           flexibility in when the fork happens.  `add_sockets` can
           also be used in single-process servers if you want to create
           your listening sockets in some way other than
           `tornado.netutil.bind_sockets`.

        */

        public Action<HTTPRequest> request_callback;
        public bool no_keep_alive;
        public bool xheaders;

        public HTTPServer(Action<HTTPRequest> request_callback_, bool no_keep_alive_ = false, IOLoop io_loop_ = null, bool xheaders_ = false, object ssl_options_ = null)
            : base(io_loop_, ssl_options_)
        {
            request_callback = request_callback_;
            no_keep_alive = no_keep_alive_;
            xheaders = xheaders_;
        }

        public override void handle_stream(IOStream stream, IPEndPoint address)
        {

            new HTTPConnection(stream, address, request_callback, no_keep_alive, xheaders);
        }
    }

    public class _BadRequestException : Exception
    {
        public _BadRequestException(string message)
            : base(message)
        {
        }
    }

    public class HTTPConnection
    {
        /*Handles a connection to an HTTP client, executing HTTP requests.

        We parse HTTP headers and bodies, and execute the request callback
        until the HTTP conection is closed.
        */

        public IOStream stream;
        public IPEndPoint address;
        public Action<HTTPRequest> request_callback;
        public bool no_keep_alive;
        public bool xheaders;

        private HTTPRequest _request;
        private bool _request_finished;
        private Action<byte[]> _header_callback;
        private object _write_callback;


        public HTTPConnection(IOStream stream_, IPEndPoint address_, Action<HTTPRequest> request_callback_, bool no_keep_alive_ = false, bool xheaders_ = false)
        {
            stream = stream_;
            address = address_;
            request_callback = request_callback_;
            no_keep_alive = no_keep_alive_;
            xheaders = xheaders_;
            _request = null;
            _request_finished = false;
            // Save stack context here, outside of any request.  This keeps
            // contexts from one request from leaking into the next.
            _header_callback = _on_headers; //stack_context.wrap(self._on_headers);
            stream.read_until(Encoding.UTF8.GetBytes("\r\n\r\n"), _header_callback);
            _write_callback = null;
        }
        
        public void close()
        {
            stream.close();
            // Remove this reference to self, which would otherwise cause a
            // cycle and delay garbage collection of this connection.
            _header_callback = null;
        }

        private void _on_headers(byte[] data_)
        {
            try
            {
                string data = UTF8Encoding.UTF8.GetString(data_);
                var eol = data.IndexOf("\r\n");
                var start_line = data.Substring(0, eol);
                string method, uri, version;
                try
                {
                    // method, uri, version = start_line.Split(' ');
                    var split = start_line.Split(' ');
                    method = split[0]; uri = split[1]; version = split[2];
                }
                catch(Exception ex) // except ValueError:
                {
                    throw new _BadRequestException("Malformed HTTP request line");
                }
                if (!version.StartsWith("HTTP/"))
                    throw new _BadRequestException("Malformed HTTP version in HTTP Request-Line");
                var headers = HTTPHeaders.parse(data.Substring(eol));
                    
                // HTTPRequest wants an IP, not a full socket address
                var remote_ip = "";
                if (stream.socket.AddressFamily == AddressFamily.InterNetwork ||
                   stream.socket.AddressFamily == AddressFamily.InterNetworkV6)
                    // Jython 2.5.2 doesn't have the socket.family attribute,
                    // so just assume IP in that case.
                    remote_ip = address.Address.ToString();
                else
                    // Unix (or other) socket; fake the remote address
                    remote_ip = "0.0.0.0";

                _request = new HTTPRequest(
                    connection_: this, method_: method, uri_: uri, version_: version,
                    headers_: headers, remote_ip_: remote_ip);

                var content_length_ = headers.get("Content-Length");
                if (content_length_ != null)
                {
                    var content_length = int.Parse(content_length_);
                    if (content_length > stream.max_buffer_size)
                        throw new _BadRequestException("Content-Length too long");
                    if (headers.get("Expect") == "100-continue")
                        stream.write(UTF8Encoding.UTF8.GetBytes("HTTP/1.1 100 (Continue)\r\n\r\n"));
                    stream.read_bytes(content_length, _on_request_body);
                    return;
                }

                request_callback(_request);
            }
            catch(Exception ex)
            {
                //todo logging.info("Malformed HTTP request from %s: %s", self.address[0], e)
                close();
                return;
            }
        }

        private void _on_request_body(byte[] data)
        {
            _request.body = data;
            if(_request.method == "POST" || _request.method == "PATCH" || _request.method == "PUT" )
                ;//todo 
                /*httputil.parse_body_arguments(
                    _request.headers.get("Content-Type", ""), data,
                    _request.arguments, _request.files);*/
            request_callback(_request);
        }

    }

    public class HTTPRequest
    {
        /*A single HTTP request.

        All attributes are type `str` unless otherwise noted.

        .. attribute:: method

           HTTP request method, e.g. "GET" or "POST"

        .. attribute:: uri

           The requested uri.

        .. attribute:: path

           The path portion of `uri`

        .. attribute:: query

           The query portion of `uri`

        .. attribute:: version

           HTTP version specified in request, e.g. "HTTP/1.1"

        .. attribute:: headers

           `HTTPHeader` dictionary-like object for request headers.  Acts like
           a case-insensitive dictionary with additional methods for repeated
           headers.

        .. attribute:: body

           Request body, if present, as a byte string.

        .. attribute:: remote_ip

           Client's IP address as a string.  If `HTTPServer.xheaders` is set,
           will pass along the real IP address provided by a load balancer
           in the ``X-Real-Ip`` header

        .. attribute:: protocol

           The protocol used, either "http" or "https".  If `HTTPServer.xheaders`
           is set, will pass along the protocol used by a load balancer if
           reported via an ``X-Scheme`` header.

        .. attribute:: host

           The requested hostname, usually taken from the ``Host`` header.

        .. attribute:: arguments

           GET/POST arguments are available in the arguments property, which
           maps arguments names to lists of values (to support multiple values
           for individual names). Names are of type `str`, while arguments
           are byte strings.  Note that this is different from
           `RequestHandler.get_argument`, which returns argument values as
           unicode strings.

        .. attribute:: files

           File uploads are available in the files property, which maps file
           names to lists of :class:`HTTPFile`.

        .. attribute:: connection

           An HTTP request is attached to a single HTTP connection, which can
           be accessed through the "connection" attribute. Since connections
           are typically kept open in HTTP/1.1, multiple requests can be handled
           sequentially on a single connection.
        */

        public string method;
        public string uri;
        public string version;
        public HTTPHeaders headers;
        public byte[] body;
        public string remote_ip;
        public string protocol;
        public string host;
        public HTTPConnection connection;

        public HTTPRequest(string method_, string uri_, string version_="HTTP/1.0", HTTPHeaders headers_=null,
                     byte[] body_=null, string remote_ip_=null, string protocol_=null, string host_=null,
                     string files=null, HTTPConnection connection_=null)
        {
            method = method_;
            uri = uri_;
            version = version_;
            headers = headers_ ?? new HTTPHeaders();
            body = body_ ?? new byte[] {};
            if (connection != null && connection.xheaders)
            {
                // Squid uses X-Forwarded-For, others use X-Real-Ip
                remote_ip = headers.get(
                    "X-Real-Ip", headers.get("X-Forwarded-For", remote_ip_));
                if (!_valid_ip(remote_ip))
                    remote_ip = remote_ip_;
                // AWS uses X-Forwarded-Proto
                protocol = headers.get(
                    "X-Scheme", headers.get("X-Forwarded-Proto", protocol_));
                if (protocol != "http" && protocol != "https")
                    protocol = "http";
            }
            else
            {
                remote_ip = remote_ip_;
                if (protocol_ != null)
                    protocol = protocol_;
                //todo ssl else if (connection != null && isinstance(connection.stream, iostream.SSLIOStream):
                //    protocol = "https"
                else
                    protocol = "http";
            }
            host = host_ ?? headers.get("Host") ?? "127.0.0.1";
            //todo files = files_ ?? {}
            connection = connection_;
            //todo
            /*_start_time = time.time()
            _finish_time = None

            path, sep, query = uri.partition('?')
            arguments = parse_qs_bytes(query)
            arguments = {}
            for name, values in arguments.iteritems():
                values = [v for v in values if v]
                if values:
                    arguments[name] = values*/
        }

        public bool supports_http_1_1()
        {
            //Returns True if this request supports HTTP/1.1 semantics
            return version == "HTTP/1.1";
        }

        private bool _valid_ip(string ip)
        {
            try
            {
                /*res = socket.getaddrinfo(ip, 0, socket.AF_UNSPEC,
                                         socket.SOCK_STREAM,
                                         0, socket.AI_NUMERICHOST)*/

                var res = Dns.GetHostEntry(ip);

                return (res != null);
            }
            catch(SocketException e)
            {
                //todo what code is this?? if e.args[0] == socket.EAI_NONAME:
                //    return False
                throw;
            }
            return true;
        }
    }
}
