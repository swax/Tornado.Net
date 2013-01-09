using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Tornado.httpserver;
using Tornado.httputil;


namespace Tornado.web
{
    public class RequestHandler
    {
        /*Subclass this class and define get() or post() to make a handler.

        If you want to support more methods than the standard GET/HEAD/POST, you
        should override the class variable SUPPORTED_METHODS in your
        RequestHandler class.
        */
        string[] SUPPORTED_METHODS = new string[] {"GET", "HEAD", "POST", "DELETE", "PATCH", "PUT",
                             "OPTIONS"};

        //_template_loaders = {}  // {path: template.BaseLoader}
        //_template_loader_lock = threading.Lock()

        public Application application;
        public HTTPRequest request;
        private bool _headers_written;
        private bool _finished;
        private bool _auto_finish;
        private int _status_code;
        private Dictionary<string, string> _headers;
        private TupleList<string, string> _list_headers;
        private List<object> _write_buffer;

        public RequestHandler() { }

        public RequestHandler(Application application_, HTTPRequest request_, Dictionary<string, string> kwargs)
        {
            //def __init__(self, application, request, **kwargs):
            //super(RequestHandler, self).__init__()

            application = application_;
            request = request_;
            _headers_written = false;
            _finished = false;
            _auto_finish = true;
            //todo implement
            /*self._transforms = None  // will be set in _execute
            self.ui = ObjectDict((n, self._ui_method(m)) for n, m in
                         application.ui_methods.iteritems())*/
            // UIModules are available as both `modules` and `_modules` in the
            // template namespace.  Historically only `modules` was available
            // but could be clobbered by user additions to the namespace.
            // The template {% module %} directive looks in `_modules` to avoid
            // possible conflicts.
            /*self.ui["_modules"] = ObjectDict((n, self._ui_module(n, m)) for n, m in
                                     application.ui_modules.iteritems())
            self.ui["modules"] = self.ui["_modules"]*/
            clear();
            // Check since connection is not available in WSGI
            /*if getattr(self.request, "connection", None):
                self.request.connection.stream.set_close_callback(
                    self.on_connection_close)*/
            initialize(kwargs);
        }

        public virtual void initialize(Dictionary<string, string> kwargs)
        {
            /*Hook for subclass initialization.

            A dictionary passed as the third argument of a url spec will be
            supplied as keyword arguments to initialize().

            Example::

                class ProfileHandler(RequestHandler):
                    def initialize(self, database):
                        self.database = database

                    def get(self, username):
                        ...

                app = Application([
                    (r'/user/(.*)', ProfileHandler, dict(database=database)),
                    ])
            */
            return;
        }

        public void clear()
        {
            //Resets all headers and content for this response."""
            // The performance cost of tornado.httputil.HTTPHeaders is significant
            // (slowing down a benchmark with a trivial handler by more than 10%),
            // and its case-normalization is not generally necessary for
            // headers we generate on the server side, so use a plain dict
            // and list instead.
            _headers = new Dictionary<string,string>() {
                {"Server", "TornadoServer/" + tornado.version},
                {"Content-Type", "text/html; charset=UTF-8"}
            };
            _list_headers = new TupleList<string,string>();
            set_default_headers();
            if (!request.supports_http_1_1())
                if (request.headers.get("Connection") == "Keep-Alive")
                    set_header("Connection", "Keep-Alive");
            _write_buffer = new List<object>();
            _status_code = 200;
        }

        public virtual void set_default_headers()
        {
            /*Override this to set HTTP headers at the beginning of the request.

            For example, this is the place to set a custom ``Server`` header.
            Note that setting such headers in the normal flow of request
            processing may not do what you want, since headers may be reset
            during error handling.
            */
            return;
        }

        public void set_status(int status_code)
        {
            // Sets the status code for our response.
            //todo assert status_code in httplib.responses;
            _status_code = status_code;
        }

        public void set_header(string name, object value)
        {
            /*Sets the given response header name and value.

            If a datetime is given, we automatically format it according to the
            HTTP specification. If the value is not a string, we convert it to
            a string. All header values are then encoded as UTF-8.
            */
            _headers[name] = _convert_header_value(value);
        }

        private string _convert_header_value(object value)
        {
            if (value.GetType() == typeof(byte[]))
                ;
            else if(value.GetType() == typeof(string))
                ;
            else if (value.GetType() == typeof(int) || value.GetType() == typeof(long))
                // return immediately since we know the converted value will be safe
                return value.ToString();
            else if (value.GetType() == typeof(DateTime))
            {
                // todo implement
                //var t = calendar.timegm(value.utctimetuple())
                //return email.utils.formatdate(t, localtime=False, usegmt=True)
            }
            else
                throw new Exception("Unsupported header value " + value.ToString());
            // If \n is allowed into the header, it is possible to inject
            // additional headers or split the request. Also cap length to
            // prevent obviously erroneous values.
            //todo implement 
            //if len(value) > 4000 or re.search(b(r"[\x00-\x1f]"), value):
            //    raise ValueError("Unsafe header value %r", value)
            return value.ToString();
        }

        public void redirect(string url, bool permanent=false, int status=0)
        {
            /*Sends a redirect to the given (optionally relative) URL.

            If the ``status`` argument is specified, that value is used as the
            HTTP status code; otherwise either 301 (permanent) or 302
            (temporary) is chosen based on the ``permanent`` argument.
            The default is 302 (temporary).
            */
            if (_headers_written)
                throw new Exception("Cannot redirect after headers have been written");
            if (status == 0)
                status = permanent ? 301 : 302;
            else
                Debug.Assert(300 <= status && status <= 399);
            set_status(status);
            // Remove whitespace
            url = Regex.Replace(url, @"[\x00-\x20]+", ""); // re.sub(b(r, "", utf8(url));
            set_header("Location", urlparse.urljoin(request.uri, url));
            finish();
        }

        public void write(object chunk)
        {
            /*Writes the given chunk to the output buffer.

            To write the output to the network, use the flush() method below.

            If the given chunk is a dictionary, we write it as JSON and set
            the Content-Type of the response to be application/json.
            (if you want to send JSON as a different Content-Type, call
            set_header *after* calling write()).

            Note that lists are not converted to JSON because of a potential
            cross-site security vulnerability.  All JSON output should be
            wrapped in a dictionary.  More details at
            http://haacked.com/archive/2008/11/20/anatomy-of-a-subtle-json-vulnerability.aspx
            */
            if (_finished)
                throw new RuntimeError("Cannot write() after finish().  May be caused " +
                                       "by using async operations without the " +
                                       "@asynchronous decorator.");
            //todo implement
            /*
            if isinstance(chunk, dict):
                chunk = escape.json_encode(chunk)
                self.set_header("Content-Type", "application/json; charset=UTF-8")*/
            var chunk_ = chunk.ToString();
            _write_buffer.Add(chunk_);
        }

        public void finish(object chunk=null)
        {
            // Finishes this response, ending the HTTP request.
            if (_finished)
                throw new RuntimeError("finish() called twice.  May be caused " +
                                       "by using async operations without the " +
                                       "@asynchronous decorator.");

            if (chunk != null)
                write(chunk);

            // Automatically support ETags and add the Content-Length header if
            // we have not flushed any content yet.
            /*if not self._headers_written:
                if (self._status_code == 200 and
                    self.request.method in ("GET", "HEAD") and
                    "Etag" not in self._headers):
                    etag = self.compute_etag()
                    if etag is not None:
                        self.set_header("Etag", etag)
                        inm = self.request.headers.get("If-None-Match")
                        if inm and inm.find(etag) != -1:
                            self._write_buffer = []
                            self.set_status(304)
                if self._status_code == 304:
                    assert not self._write_buffer, "Cannot send body with 304"
                    self._clear_headers_for_304()
                elif "Content-Length" not in self._headers:
                    content_length = sum(len(part) for part in self._write_buffer)
                    self.set_header("Content-Length", content_length)

            if hasattr(self.request, "connection"):
                # Now that the request is finished, clear the callback we
                # set on the IOStream (which would otherwise prevent the
                # garbage collection of the RequestHandler when there
                # are keepalive connections)
                self.request.connection.stream.set_close_callback(None)

            if not self.application._wsgi:
                self.flush(include_footers=True)
                self.request.finish()
                self._log()
            self._finished = True
            self.on_finish()*/
        }
    }

    public class Application
    {
        public List<Func<HTTPRequest, OutputTransform>> transforms;
        public TupleList<Regex, List<URLSpec>> handlers;
        public Dictionary<string, object> named_handlers;
        public string default_host;
        public Dictionary<string, object> settings;

        private bool _wsgi;


        public Application(TupleList<string, Func<RequestHandler>, Dictionary<string, string>> handlers_ = null, string default_host_ = "", List<Func<HTTPRequest, OutputTransform>> transforms_ = null,
                 bool wsgi=false, Dictionary<string, object> settings_=null)
        {
            if (settings_ == null) 
                settings_ = new Dictionary<string, object>();

            if (transforms_ == null)
            {
                transforms = new List<Func<HTTPRequest, OutputTransform>>();
                if (settings_.get("gzip") != null)
                    transforms.Add(r => new GZipContentEncoding(r));
                transforms.Add(r => new ChunkedTransferEncoding(r));
            }
            else
                transforms = transforms_;
            handlers = new TupleList<Regex,List<URLSpec>>();
            named_handlers = new Dictionary<string, object>();
            default_host = default_host_;
            settings = settings_;
            //todo implement
            /*self.ui_modules = {'linkify': _linkify,
                               'xsrf_form_html': _xsrf_form_html,
                               'Template': TemplateModule,
                               }
            self.ui_methods = {}*/
            _wsgi = wsgi;
            /*self._load_ui_modules(settings.get("ui_modules", {}))
            self._load_ui_methods(settings.get("ui_methods", {}))*/
            if (settings.get("static_path") != null)
            {
                var path = settings["static_path"] as string;
                handlers_ = handlers_ ?? new TupleList<string,Func<RequestHandler>,Dictionary<string, string>>();
                var static_url_prefix = settings.get("static_url_prefix", "/static/");
                var static_handler_class = settings.get<Func<RequestHandler>>("static_handler_class", () => new StaticFileHandler());
                var static_handler_args = settings.get("static_handler_args", new Dictionary<string, string>());
                static_handler_args["path"] = path;

                foreach (var pattern in new string[] {Regex.Escape(static_url_prefix) + @"(.*)", 
                                                     @"/(favicon\.ico)", @"/(robots\.txt)"}) 
                {
                    handlers_.Insert(0, Tuple.Create(pattern, static_handler_class, static_handler_args));
                }
            }
            if (handlers_ != null)
                add_handlers(".*$", handlers_);

            //todo implement
            // Automatically reload modified modules
            /*if self.settings.get("debug") and not wsgi:
                from tornado import autoreload
                autoreload.start()*/
        }

        public void Listen(int port, string address="")
        {
            /*Starts an HTTP server for this application on the given port.

            This is a convenience alias for creating an HTTPServer object
            and calling its listen method.  Keyword arguments not
            supported by HTTPServer.listen are passed to the HTTPServer
            constructor.  For advanced uses (e.g. preforking), do not use
            this method; create an HTTPServer and call its bind/start
            methods directly.

            Note that after calling this method you still need to call
            IOLoop.instance().start() to start the server.
            */
            
            // import is here rather than top level because HTTPServer
            // is not importable on appengine
            var server = new HTTPServer(Call);
            server.listen(port, address);
        }

        public void add_handlers(string host_pattern, TupleList<string, Func<RequestHandler>, Dictionary<string, string>> host_handlers)
        {
            /*Appends the given handlers to our handler list.

            Note that host patterns are processed sequentially in the
            order they were added, and only the first matching pattern is
            used.  This means that all handlers for a given host must be
            added in a single add_handlers call.
            */
            if (!host_pattern.EndsWith("$"))
                host_pattern += "$";
            var handlers_ = new List<URLSpec>();
            // The handlers with the wildcard host_pattern are a special
            // case - they're added in the constructor but should have lower
            // precedence than the more-precise handlers added later.
            // If a wildcard handler group exists, it should always be last
            // in the list, so insert new groups just before it.
            if (handlers.Any() && handlers.Last().Item1.ToString() == ".*$")
                handlers.Insert(handlers.Count - 1, Tuple.Create(new Regex(host_pattern, RegexOptions.Compiled), handlers_));
            else
                handlers.Add(Tuple.Create(new Regex(host_pattern, RegexOptions.Compiled), handlers_));

            foreach (var spec in host_handlers)
            {
                URLSpec spec_ = null;

                //todo? if type(spec) is type(()):
                {
                    //assert len(spec) in (2, 3)
                    var pattern = spec.Item1;
                    var handler = spec.Item2;

                    /*if isinstance(handler, str):
                        # import the Module and instantiate the class
                        # Must be a fully qualified name (module.ClassName)
                        handler = import_object(handler)*/

                    /*if len(spec) == 3:
                        kwargs = spec[2]
                    else:
                        kwargs = {}*/
                    var kwargs = spec.Item3;
                    spec_ = new URLSpec(pattern, handler, kwargs);
                }
                handlers_.Add(spec_);
                if (spec_.name != null)
                {
                    if (named_handlers.ContainsKey(spec_.name))
                        ;//todo logging.warning("Multiple handlers named %s; replacing previous value", spec_.name);
                    named_handlers[spec_.name] = spec_;
                }
            }
        }

        private List<URLSpec> _get_host_handlers(HTTPRequest request)
        {
            var host = request.host.ToLowerInvariant().Split(':')[0];
            foreach (var handler in handlers)
            {
                var pattern = handler.Item1;
                var handlers_ = handler.Item2;

                if (pattern.IsMatch(host))
                    return handlers_;
            }
            // Look for default host if not behind load balancer (for debugging)
            if (!request.headers.ContainsKey("X-Real-Ip"))
                foreach (var handler in handlers)
                {
                    var pattern = handler.Item1;
                    var handlers_ = handler.Item2;
                    if (pattern.IsMatch(default_host))
                        return handlers_;
                }
            return null;
        }

        public void Call(HTTPRequest request)
        {
            // Called by HTTPServer to execute the request.
            var transforms_ = transforms.Select(t => t(request));
            object handler = null;
            var args = new List<object>();
            var kwargs = new Dictionary<string, string>();
            var handlers_ = _get_host_handlers(request);
            if (handlers == null || !handlers.Any())
                handler = new RedirectHandler(this, 
                    request, new Dictionary<string, string>(){{"url", "http://" + default_host + "/"}});
            /*else
            {
                for spec in handlers:
                    match = spec.regex.match(request.path)
                    if match:
                        handler = spec.handler_class(self, request, **spec.kwargs)
                        if spec.regex.groups:
                            // None-safe wrapper around url_unescape to handle
                            // unmatched optional groups correctly
                            def unquote(s):
                                if s is None:
                                    return s
                                return escape.url_unescape(s, encoding=None)
                            // Pass matched groups to the handler.  Since
                            // match.groups() includes both named and unnamed groups,
                            // we want to use either groups or groupdict but not both.
                            // Note that args are passed as bytes so the handler can
                            // decide what encoding to use.

                            if spec.regex.groupindex:
                                kwargs = dict(
                                    (str(k), unquote(v))
                                    for (k, v) in match.groupdict().iteritems())
                            else:
                                args = [unquote(s) for s in match.groups()]
                        break
                if not handler:
                    handler = ErrorHandler(self, request, status_code=404)
            }
            // In debug mode, re-compile templates and reload static files on every
            // request so you don't need to restart to see changes
            if self.settings.get("debug"):
                with RequestHandler._template_loader_lock:
                    for loader in RequestHandler._template_loaders.values():
                        loader.reset()
                StaticFileHandler.reset()

            handler._execute(transforms, *args, **kwargs)
            return handler*/
        }
    }

    class RedirectHandler : RequestHandler
    {
       /*Redirects the client to the given URL for all GET requests.

        You should provide the keyword argument "url" to the handler, e.g.::

            application = web.Application([
                (r"/oldpath", web.RedirectHandler, {"url": "/newpath"}),
            ])
        */

        private string _url;
        private bool _permanent;

        public RedirectHandler(Application application_, HTTPRequest request_, Dictionary<string, string> kwargs)
            : base(application_, request_, kwargs)
        {
        }

        public void initialize(string url, bool permanent=true)
        {
            _url = url;
            _permanent = permanent;
        }

        public void get()
        {
            redirect(_url, _permanent);
        }
    }

    public class StaticFileHandler : RequestHandler
    {
        public StaticFileHandler() 
        {

        }

    }

    public class OutputTransform
    {
        /*A transform modifies the result of an HTTP request (e.g., GZip encoding)

        A new transform instance is created for every request. See the
        ChunkedTransferEncoding example below if you want to implement a
        new Transform.
        */
        public OutputTransform(HTTPRequest request)
        {

        }

        public virtual Tuple<int, HTTPHeaders, byte[]>  transform_first_chunk(int status_code, HTTPHeaders headers, byte[] chunk, bool finishing)
        {
            return new Tuple<int,HTTPHeaders,byte[]>(status_code, headers, chunk);
        }

        public virtual byte[] transform_chunk(byte[] chunk, bool finishing)
        {
            return chunk;
        }
    }

    public class GZipContentEncoding : OutputTransform
    {
        /*Applies the gzip content encoding to the response.

        See http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.11
        */
        string[] CONTENT_TYPES = new string[] {
        "text/plain", "text/html", "text/css", "text/xml", "application/javascript",
        "application/x-javascript", "application/xml", "application/atom+xml",
        "text/javascript", "application/json", "application/xhtml+xml"};
        int MIN_LENGTH = 5;

        private bool _gzipping;
        private MemoryStream _gzip_value;
        private GZipStream _gzip_file;


        public GZipContentEncoding(HTTPRequest request)
            : base(request)
        {
            _gzipping = request.supports_http_1_1() &&
                request.headers.get("Accept-Encoding", "").Contains("gzip");
        }

        public override Tuple<int, HTTPHeaders, byte[]> transform_first_chunk(int status_code, HTTPHeaders headers, byte[] chunk, bool finishing)
        {
            if (_gzipping)
            {
                var ctype = headers.get("Content-Type", "").Split(';')[0];
                _gzipping = CONTENT_TYPES.Contains(ctype) &&
                    (!finishing || chunk.Length >= MIN_LENGTH) &&
                    (finishing || !headers.ContainsKey("Content-Length")) &&
                    (!headers.ContainsKey("Content-Encoding"));
            }
            if (_gzipping)
            {
                headers["Content-Encoding"] = "gzip";
                _gzip_value = new MemoryStream(); // BytesIO();
                //_gzip_file = gzip.GzipFile(mode = "w", fileobj = self._gzip_value);
                _gzip_file = new GZipStream(_gzip_value, CompressionMode.Compress);
                chunk = transform_chunk(chunk, finishing);
                if (headers.ContainsKey("Content-Length"))
                    headers["Content-Length"] = chunk.Length.ToString();
            }
            return new Tuple<int, HTTPHeaders, byte[]>(status_code, headers, chunk);
        }

        public override byte[] transform_chunk(byte[] chunk, bool finishing)
        {
            if (_gzipping)
            {
                _gzip_file.Write(chunk, 0, chunk.Length);
                if (finishing)
                    _gzip_file.Close();
                else
                    _gzip_file.Flush();
                chunk = _gzip_value.ToArray(); // getvalue();
                _gzip_value.SetLength(0); //truncate(0);
                _gzip_value.Seek(0, SeekOrigin.Begin);
            }
            return chunk;
        }
    }

    public class ChunkedTransferEncoding : OutputTransform
    {
        /*Applies the chunked transfer encoding to the response.

        See http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
        */

        private bool _chunking;

        public ChunkedTransferEncoding(HTTPRequest request)
            : base(request)
        {
            _chunking = request.supports_http_1_1();
        }

        public override Tuple<int, HTTPHeaders, byte[]> transform_first_chunk(int status_code, HTTPHeaders headers, byte[] chunk, bool finishing)
        {
            // 304 responses have no body (not even a zero-length body), and so
            // should not have either Content-Length or Transfer-Encoding headers.
            if (_chunking && status_code != 304)
            {
                // No need to chunk the output if a Content-Length is specified
                if (headers.ContainsKey("Content-Length") || headers.ContainsKey("Transfer-Encoding"))
                    _chunking = false;
                else
                {
                    headers["Transfer-Encoding"] = "chunked";
                    chunk = transform_chunk(chunk, finishing);
                }
            }
            return new Tuple<int, HTTPHeaders, byte[]>(status_code, headers, chunk);
        }

        public override byte[] transform_chunk(byte[] block, bool finishing)
        {
            if (_chunking)
            {
                // Don't write out empty chunks because that means END-OF-STREAM
                // with chunked encoding
                if (block.Length > 0)
                    block = ByteArrayExtensions.join(UTF8Encoding.UTF8.GetBytes(block.Length + "\r\n"), block, UTF8Encoding.UTF8.GetBytes("\r\n"));
                if (finishing)
                    block = ByteArrayExtensions.join(block, UTF8Encoding.UTF8.GetBytes("\0\r\n\r\n"));
            }
            return block;
        }
    }

    public class URLSpec
    {
        public Regex regex;
        public Func<RequestHandler> handler_class;
        public Dictionary<string,string> kwargs;
        public string name;

        //Specifies mappings between URLs and handlers.
        public URLSpec(string pattern, Func<RequestHandler> handler_class_, Dictionary<string,string> kwargs_=null, string name_=null)
        {
            /*Creates a URLSpec.

            Parameters:

            pattern: Regular expression to be matched.  Any groups in the regex
                will be passed in to the handler's get/post/etc methods as
                arguments.

            handler_class: RequestHandler subclass to be invoked.

            kwargs (optional): A dictionary of additional arguments to be passed
                to the handler's constructor.

            name (optional): A name for this handler.  Used by
                Application.reverse_url.
            */
            if (pattern.EndsWith("$"))
                pattern += '$';
            regex = new Regex(pattern, RegexOptions.Compiled);
            /*Debug.len(self.regex.groupindex) in (0, self.regex.groups), \
                ("groups in url regexes must either be all named or all "
                 "positional: %r" % self.regex.pattern)*/
            handler_class = handler_class_;
            kwargs = kwargs_ ?? new Dictionary<string,string>();
            name = name_;
            //todo _path, self._group_count = self._find_groups();
        }
    }
}


