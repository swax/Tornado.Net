using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

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
        private List<OutputTransform> _transforms;

        protected int _status_code;
        private HTTPHeaders _headers;
        private TupleList<string, string> _list_headers;
        private List<byte[]> _write_buffer;
        private string _xsrf_token;
        private SimpleCookie _new_cookie;
        private object _current_user;


        public RequestHandler() { }

        public RequestHandler(Application application_, HTTPRequest request_, Dictionary<string, object> kwargs)
        {
            //def __init__(self, application, request, **kwargs):
            //super(RequestHandler, self).__init__()

            application = application_;
            request = request_;
            _headers_written = false;
            _finished = false;
            _auto_finish = true;

            _transforms = null;  // will be set in _execute
            //todo implement 
            /*self.ui = ObjectDict((n, self._ui_method(m)) for n, m in
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
            if (request.connection != null)
                request.connection.stream.set_close_callback(on_connection_close);
            initialize(kwargs);
        }

        public virtual void initialize(Dictionary<string, object> kwargs)
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

 
        public Dictionary<string,object> settings()
        {
            //An alias for `self.application.settings`."""
            return application.settings;
        }

        public virtual void head()
        {
            throw new HTTPError(405);
        }

        public virtual void get()
        {
            throw new HTTPError(405);
        }

        public virtual void post()
        {
            throw new HTTPError(405);
        }

        public virtual void delete()
        {
            throw new HTTPError(405);
        }

        public virtual void patch()
        {
            throw new HTTPError(405);
        }

        public virtual void put()
        {
            throw new HTTPError(405);
        }

        public virtual void options()
        {
            throw new HTTPError(405);
        }

        public virtual void prepare()
        {
            /*Called at the beginning of a request before `get`/`post`/etc.

            Override this method to perform common initialization regardless
            of the request method.
            */
            return;
        }

        public virtual void on_finish()
        {
            /*Called after the end of a request.

            Override this method to perform cleanup, logging, etc.
            This method is a counterpart to `prepare`.  ``on_finish`` may
            not produce any output, as it is called after the response
            has been sent to the client.
            */
            return;
        }

        public virtual void on_connection_close()
        {
            /*Called in async handlers if the client closed the connection.

            Override this to clean up resources associated with
            long-lived connections.  Note that this method is called only if
            the connection was closed during asynchronous processing; if you
            need to do cleanup after every request override `on_finish`
            instead.

            Proxies may keep a connection open for a time (perhaps
            indefinitely) after the client has gone away, so this method
            may not be called promptly after the end user closes their
            connection.
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
            _headers = new HTTPHeaders {
                {"Server", "TornadoServer/" + tornado.version},
                {"Content-Type", "text/html; charset=UTF-8"}
            };
            _list_headers = new TupleList<string,string>();
            set_default_headers();
            if (!request.supports_http_1_1())
                if (request.headers.get("Connection") == "Keep-Alive")
                    set_header("Connection", "Keep-Alive");
            _write_buffer = new List<byte[]>();
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

        public void clear_header(string name)
        {
            /*Clears an outgoing header, undoing a previous `set_header` call.

            Note that this method does not apply to multi-valued headers
            set by `add_header`.
            */
            if (_headers.ContainsKey(name))
                _headers.Remove(name);
        }

        const string _ARG_DEFAULT = "";//[]

        public string get_argument(string name, string default_=_ARG_DEFAULT, bool strip=true)
        {
            /*Returns the value of the argument with the given name.

            If default is not provided, the argument is considered to be
            required, and we throw an HTTP 400 exception if it is missing.

            If the argument appears in the url more than once, we return the
            last value.

            The returned value is always unicode.
            */
            var args = get_arguments(name, strip);
            if (args == null)
            {
                if (default_ == _ARG_DEFAULT)
                    throw new HTTPError(400, "Missing argument" + name);
                return default_;
            }
            return args.LastOrDefault();
        }

        public List<string> get_arguments(string name, bool strip=true)
        {
            /*Returns a list of the arguments with the given name.

            If the argument is not present, returns an empty list.

            The returned values are always unicode.
            */
            var values = new List<string>();
            foreach( var v in request.arguments.get(name, new string[]{}))
            {
                var v_ = decode_argument(v, name);
                //if isinstance(v, unicode):
                    // Get rid of any weird control chars (unless decoding gave
                    // us bytes, in which case leave it alone)
                    //todo implement v_ = re.sub(r"[\x00-\x08\x0e-\x1f]", " ", v_)
                if (strip)
                    v_ = v_.Trim();
                values.Add(v);
            }
            return values;
        }

        public string decode_argument(string value, string name=null)
        {
            /*Decodes an argument from the request.

            The argument has been percent-decoded and is now a byte string.
            By default, this method decodes the argument as utf-8 and returns
            a unicode string, but this may be overridden in subclasses.

            This method is used as a filter for both get_argument() and for
            values extracted from the url and passed to get()/post()/etc.

            The name of the argument is provided if known, but may be None
            (e.g. for unnamed groups in the url regex).
            */
            return value;//_unicode(value);
        }

        public Dictionary<string, HttpCookie> cookies
        {
            get
            {
                return request.cookies;
            }
        }

        public string get_cookie(string name, string default_=null)
        {
            //Gets the value of the cookie with the given name, else default.
            if (request.cookies != null && request.cookies.ContainsKey(name))
                return request.cookies[name].Value;
            return default_;
        }

        public void set_cookie(string name, string value, string domain=null, DateTime? expires=null, string path="/",
                   int? expires_days=null, Dictionary<string, string> kwargs=null)
        {
            /*Sets the given cookie name/value with the given options.

            Additional keyword arguments are set on the Cookie.Morsel
            directly.
            See http://docs.python.org/library/cookie.html#morsel-objects
            for available attributes.
            */
            // The cookie library only accepts type str, in both python 2 and 3
            name = escape.native_str(name);
            value = escape.native_str(value);
            if (Regex.IsMatch(name + value, "[\x00-\x20]"))
                // Don't let us accidentally inject bad stuff
                throw new ValueError(string.Format("Invalid cookie {0}: {1}", name, value));
            if (_new_cookie == null)
                _new_cookie = new SimpleCookie();
            if (_new_cookie.ContainsKey(name)) 
                _new_cookie.Remove(name);
            _new_cookie[name] = new HttpCookie(name, value);
            var morsel = _new_cookie[name];
            if (domain != null)
                morsel.Domain = domain;
            if (expires_days != null && expires == null)
                expires = DateTime.UtcNow.AddDays(expires_days.Value);
            if (expires != null)
                morsel.Expires = expires.Value;
                //timestamp = calendar.timegm(expires.utctimetuple())
                //morsel["expires"] = email.utils.formatdate(
                //    timestamp, localtime=False, usegmt=True)
            if (path != null)
                morsel.Path = path;
            if(kwargs != null)
                foreach(var kvp in kwargs)
                {
                    var k = kvp.Key;
                    if(k == "max age")
                        k = "max-age"; 
                    morsel.Values[k] = kvp.Value;
                }
        }

        public void set_status(int status_code)
        {
            // Sets the status code for our response.
            Debug.Assert(httplib.responses.ContainsKey(status_code));
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

        public void write(byte[] chunk)
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
      
            _write_buffer.Add(chunk);
        }

        public void flush(bool include_footers=false, Action callback=null)
        {
            /*Flushes the current output buffer to the network.

            The ``callback`` argument, if given, can be used for flow control:
            it will be run when all flushed data has been written to the socket.
            Note that only one flush callback can be outstanding at a time;
            if another flush occurs before the previous flush's callback
            has been run, the previous callback will be discarded.
            */
            if (application._wsgi)
                throw new Exception("WSGI applications do not support flush()");

            var chunk = ByteArrayExtensions.join(_write_buffer.ToArray());
            _write_buffer = new List<byte[]>();
            byte[] headers = null;
            if (!_headers_written)
            {
                _headers_written = true;
                foreach (var transform in _transforms)
                {
                    var result = transform.transform_first_chunk(_status_code, _headers, chunk, include_footers);
                    _status_code = result.Item1;
                    _headers = result.Item2;
                    chunk = result.Item3;
                }
                headers = _generate_headers();
            }
            else
            {
                foreach (var transform in _transforms)
                    chunk = transform.transform_chunk(chunk, include_footers);
                headers = new byte[]{};
            }

            // Ignore the chunk and only write the headers for HEAD requests
            if (request.method == "HEAD")
            {
                if (headers != null && headers.Length > 0)
                    request.write(headers, callback);
                return;
            }
                    
            request.write(ByteArrayExtensions.join(headers, chunk), callback);
        }

        public void finish(string body)
        {
            finish(UTF32Encoding.UTF8.GetBytes(body));
        }

        public void finish(byte[] chunk=null)
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
            if (!_headers_written)
            {
                if (_status_code == 200 && 
                    (request.method == "GET" || request.method == "HEAD") && 
                    !_headers.ContainsKey("Etag"))
                {
                    var etag = compute_etag();
                    if (etag != null)
                    {
                        set_header("Etag", etag);
                        var inm = request.headers.get("If-None-Match");
                        if (inm != null && inm.IndexOf(etag) != -1)
                        {
                            _write_buffer = new List<byte[]>();
                            set_status(304);
                        }
                    }
                }
                if (_status_code == 304)
                {
                    Debug.Assert(_write_buffer.Count == 0, "Cannot send body with 304");
                    _clear_headers_for_304();
                }
                else if (!_headers.ContainsKey("Content-Length"))
                {
                    var content_length = _write_buffer.Sum(p => p.Length);
                    set_header("Content-Length", content_length);
                }
            }

            if (request.connection != null)
                // Now that the request is finished, clear the callback we
                // set on the IOStream (which would otherwise prevent the
                // garbage collection of the RequestHandler when there
                // are keepalive connections)
                request.connection.stream.set_close_callback(null);

            if (!application._wsgi)
            {
                flush(true); 
                request.finish();
                //todo logging _log();
            }
            _finished = true;
            on_finish();
        }

        public void send_error(int status_code=500, Exception kwargs=null)
        {
            /*Sends the given HTTP error code to the browser.

            If `flush()` has already been called, it is not possible to send
            an error, so this method will simply terminate the response.
            If output has been written but not yet flushed, it will be discarded
            and replaced with the error page.

            Override `write_error()` to customize the error page that is returned.
            Additional keyword arguments are passed through to `write_error`.
            */
            if (_headers_written)
            {
                logging.error("Cannot send error response after headers written");
                if (!_finished)
                    finish();
                return;
            }
            clear();
            set_status(status_code);
            try
            {
                write_error(status_code, kwargs);
            }
            catch(Exception ex)
            {
                logging.error("Uncaught exception in write_error", ex);
            }
            if (!_finished)
                finish();
        }
        
        public void write_error(int status_code, Exception kwargs)
        {
            /*Override to implement custom error pages.

            ``write_error`` may call `write`, `render`, `set_header`, etc
            to produce output as usual.

            If this error was caused by an uncaught exception, an ``exc_info``
            triple will be available as ``kwargs["exc_info"]``.  Note that this
            exception may not be the "current" exception for purposes of
            methods like ``sys.exc_info()`` or ``traceback.format_exc``.

            For historical reasons, if a method ``get_error_html`` exists,
            it will be used instead of the default ``write_error`` implementation.
            ``get_error_html`` returned a string instead of producing output
            normally, and had different semantics for exception handling.
            Users of ``get_error_html`` are encouraged to convert their code
            to override ``write_error`` instead.
            */
            //todo implement?
            /*if hasattr(self, 'get_error_html'):
                if 'exc_info' in kwargs:
                    exc_info = kwargs.pop('exc_info')
                    kwargs['exception'] = exc_info[1]
                    try:
                        # Put the traceback into sys.exc_info()
                        raise_exc_info(exc_info)
                    except Exception:
                        self.finish(self.get_error_html(status_code, **kwargs))
                else:
                    self.finish(self.get_error_html(status_code, **kwargs))
                return
            if (settings.get("debug") != null) // and "exc_info" in kwargs:
            {
                // in debug mode, try to send a traceback
                set_header("Content-Type", "text/plain");
                for line in traceback.format_exception(*kwargs["exc_info"])
                    self.write(line);
                finish();
            }
            else*/
                finish(string.Format(@"<html><title>{0}: {1}</title>
                                    <body>{0}: {1}</body></html>",
                                    status_code,
                                    httplib.responses[status_code]
                                  ));
        }

        public object current_user
        {
            get
            {
                /*The authenticated user for this request.

                Determined by either get_current_user, which you can override to
                set the user based on, e.g., a cookie. If that method is not
                overridden, this method always returns None.

                We lazy-load the current user the first time this method is called
                and cache the result after that.
                */
                if (_current_user == null)
                    _current_user = get_current_user_();
                return _current_user;
            }
        }

        public virtual object get_current_user_()
        {
            //Override to determine the current user from, e.g., a cookie.
            return null;
        }

        public string xsrf_token
        {
            get
            {
                /*The XSRF-prevention token for the current user/session.

                To prevent cross-site request forgery, we set an '_xsrf' cookie
                and include the same '_xsrf' value as an argument with all POST
                requests. If the two do not match, we reject the form submission
                as a potential forgery.

                See http://en.wikipedia.org/wiki/Cross-site_request_forgery
                */
                if (_xsrf_token == null)
                {
                    var token = get_cookie("_xsrf");
                    if (token == null)
                    {
                        token = Guid.NewGuid().ToString().Replace("-", "");// binascii.b2a_hex(uuid.uuid4().bytes);
                        int expires_days = (current_user != null) ? 30 : 0;
                        set_cookie("_xsrf", token, expires_days: expires_days);
                    }
                    _xsrf_token = token;
                }
                return _xsrf_token;
            }
        }

        public void check_xsrf_cookie()
        {
            /*Verifies that the '_xsrf' cookie matches the '_xsrf' argument.

            To prevent cross-site request forgery, we set an '_xsrf'
            cookie and include the same value as a non-cookie
            field with all POST requests. If the two do not match, we
            reject the form submission as a potential forgery.

            The _xsrf value may be set as either a form field named _xsrf
            or in a custom HTTP header named X-XSRFToken or X-CSRFToken
            (the latter is accepted for compatibility with Django).

            See http://en.wikipedia.org/wiki/Cross-site_request_forgery

            Prior to release 1.1.1, this check was ignored if the HTTP header
            "X-Requested-With: XMLHTTPRequest" was present.  This exception
            has been shown to be insecure and has been removed.  For more
            information please see
            http://www.djangoproject.com/weblog/2011/feb/08/security/
            http://weblog.rubyonrails.org/2011/2/8/csrf-protection-bypass-in-ruby-on-rails
            */
            var token = (get_argument("_xsrf", null) ??
                     request.headers.get("X-Xsrftoken") ??
                     request.headers.get("X-Csrftoken"));
            if (token == null)
                throw new HTTPError(403, "'_xsrf' argument missing from POST");
            if (xsrf_token != token)
                throw new HTTPError(403, "XSRF cookie does not match POST argument");
        }

        public string compute_etag()
        {
            /*Computes the etag header to be used for this request.

            May be overridden to provide custom etag implementations,
            or may return None to disable tornado's default etag support.
            */
            var hasher = new System.Security.Cryptography.SHA1Managed();

            foreach(var part in _write_buffer)
                hasher.TransformBlock(part, 0, part.Length, part, 0);

            hasher.TransformFinalBlock(new byte[] {}, 0, 0);

            return BitConverter.ToString(hasher.Hash).Replace("-", "").ToLower();
        }

        public void _execute(List<OutputTransform> transforms, List<string> args, Dictionary<string, string> kwargs)
        {
            //Executes this request with the given output transforms.
            _transforms = transforms;
            try
            {
                if (!SUPPORTED_METHODS.Contains(request.method))
                    throw new HTTPError(405);

                // If XSRF cookies are turned on, reject form submissions without
                // the proper cookie
                // todo cookies 
                if (request.method != "GET" && request.method != "HEAD" && request.method != "OPTIONS" && 
                    application.settings.get("xsrf_cookies") != null)
                    check_xsrf_cookie();
                prepare();
                if (!_finished)
                {
                    // todo implement args
                    /*var args = [self.decode_argument(arg) for arg in args]
                    var kwargs = dict((k, self.decode_argument(v, name=k))
                                  for (k, v) in kwargs.iteritems())
                    getattr(self, self.request.method.lower())(*args, **kwargs)*/
                   
                    //todo wouldnt the reflection above be really slow here?
                    var req = request.method.ToLower();
                    if (req == "head")
                        head();
                    else if (req == "get")
                        get();
                    else if (req == "post")
                        post();
                    else if (req == "delete")
                        delete();
                    else if (req == "patch")
                        patch();
                    else if (req == "put")
                        put();
                    else if (req == "options")
                        options();

                    if (_auto_finish && !_finished)
                        finish();
                }
            }
            catch(Exception e)
            {
                _handle_request_exception(e);
            }
        }

        public byte[] _generate_headers()
        {
            var lines = new List<string>() {request.version + " " +
                          _status_code.ToString() +
                          " " + httplib.responses[_status_code]};

            foreach(var nv in _headers)
                lines.Add(nv.Key + ": " + nv.Value);
            foreach(var nv in _list_headers)
                lines.Add(nv.Item1 + ": " + nv.Item2);

            if (_new_cookie != null)
                foreach (var cookie in _new_cookie.Values)
                    lines.Add("Set-Cookie: " + cookie.ToString()); //todo is this the same as + cookie.OutputString(None)?

            return UTF8Encoding.UTF8.GetBytes(String.Join("\r\n", lines) + "\r\n\r\n");
        }

        public string _request_summary()
        {
            return request.method + " " + request.uri +
                " (" + request.remote_ip + ")";
        }

        public void _handle_request_exception(Exception e)
        {
            if (e is HTTPError)
            {
                var e_ = e as HTTPError;
                if (e_.log_message != null)
                {
                    /*format = "%d %s: " + e.log_message
                    args = [e.status_code, self._request_summary()] + list(e.args)
                    logging.warning(format, *args)*/
                    var prefix = string.Format("{0} {1}: ", e_.status_code, _request_summary());
                    var suffix = string.Format(e_.log_message, e_.args);
                    logging.warning(prefix + suffix);
                }
                if (!httplib.responses.ContainsKey(e_.status_code))
                {
                    logging.error("Bad HTTP status code: " + e_.status_code);
                    send_error(500, e_);
                }
                else
                    send_error(e_.status_code, e_);
            }
            else
            {
                logging.error(string.Format("Uncaught exception {0}\n{1}", _request_summary(),
                              request), e);
                send_error(500, e);
            }
        }

        private void _clear_headers_for_304()
        {
            // 304 responses should not contain entity headers (defined in
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html#sec7.1)
            // not explicitly allowed by
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.5
            var headers = new string[] {"Allow", "Content-Encoding", "Content-Language",
                   "Content-Length", "Content-MD5", "Content-Range",
                   "Content-Type", "Last-Modified"};
            foreach (var h in headers)
                clear_header(h);
        }
    }

    public class Application
    {
        public List<Func<HTTPRequest, OutputTransform>> transforms;
        public TupleList<Regex, List<URLSpec>> handlers;
        public Dictionary<string, object> named_handlers;
        public string default_host;
        public Dictionary<string, object> settings;

        public bool _wsgi;


        public Application(TupleList<string, CreateRequestHandler, Dictionary<string, object>> handlers_ = null, string default_host_ = "", List<Func<HTTPRequest, OutputTransform>> transforms_ = null,
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
                handlers_ = handlers_ ?? new TupleList<string, CreateRequestHandler, Dictionary<string, object>>();
                var static_url_prefix = settings.get("static_url_prefix", "/static/");
                var static_handler_class = settings.get<CreateRequestHandler>("static_handler_class", (app, rq, args) => new StaticFileHandler(app, rq, args));
                var static_handler_args = settings.get("static_handler_args", new Dictionary<string, object>());
                static_handler_args["path"] = path;

                foreach (var pattern in new string[] {Regex.Escape(static_url_prefix) + @"(.*)", 
                                                     @"/(favicon\.ico)", @"/(robots\.txt)"}) 
                {
                    handlers_.Insert(0, Tuple.Create(pattern, static_handler_class, static_handler_args));
                }
            }
            if (handlers_ != null)
                add_handlers(".*$", handlers_);

      
            // Automatically reload modified modules
            if (settings.get("debug") != null && !wsgi)
            {
                //todo implement
                //from tornado import autoreload
                //autoreload.start()
            }
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

        public void add_handlers(string host_pattern, TupleList<string, CreateRequestHandler, Dictionary<string, object>> host_handlers)
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
                        logging.warning(string.Format("Multiple handlers named {0}; replacing previous value", spec_.name));
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

        public RequestHandler Call(HTTPRequest request)
        {
            // Called by HTTPServer to execute the request.
            var transforms_ = transforms.Select(t => t(request)).ToList();
            RequestHandler handler = null;
            var args = new List<string>();
            var kwargs = new Dictionary<string, string>();
            var handlers_ = _get_host_handlers(request);
            if (handlers == null || !handlers.Any())
                handler = new RedirectHandler(this, 
                    request, new Dictionary<string, object>(){{"url", "http://" + default_host + "/"}});
            else
            {
                foreach (var spec in handlers_)
                {
                    var match = spec.regex.IsMatch(request.path);
                    if (match)
                    {
                        handler = spec.handler_class(this, request, spec.kwargs);
                        // todo implement args
                        /*if spec.regex.groups:
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
                                args = [unquote(s) for s in match.groups()]*/
                        break;
                    }
                }
                if (handler == null)
                    handler = new ErrorHandler(this, request, new Dictionary<string, object>{{"status_code", 404}});
            }
            // In debug mode, re-compile templates and reload static files on every
            // request so you don't need to restart to see changes
            /*if self.settings.get("debug"):
                with RequestHandler._template_loader_lock:
                    for loader in RequestHandler._template_loaders.values():
                        loader.reset()
                StaticFileHandler.reset()*/

            handler._execute(transforms_, args, kwargs);
            return handler;
        }
    }

    public class HTTPError : Exception
    {
        public int status_code;
        public string log_message;
        public object[] args;


        // An exception that will turn into an HTTP error response.
        public HTTPError(int status_code_, string log_message_ = null, object[] args_=null)
        {
            args_ = args_ ?? new object[0];

            status_code = status_code_;
            log_message = log_message_;
            args = args_;
        }

        public override string ToString()
        {
            var message = string.Format("HTTP {0}: {1}",
               status_code, httplib.responses[status_code]);

            if (log_message != null)
                return message + " (" + string.Format(log_message, args) + ")";
            else
                return message;
        }

    }

    public class ErrorHandler : RequestHandler
    {
        // Generates an error response with status_code for all requests.

        public ErrorHandler(Application application_, HTTPRequest request_, Dictionary<string, object> kwargs)
            : base(application_, request_, kwargs)
        {
        }

        public override void initialize(Dictionary<string, object> kwargs) //int status_code)
        {
            set_status((int)kwargs["status_code"]);
        }

        public override void prepare()
        {
            throw new HTTPError(_status_code);
        }
    }

    public class RedirectHandler : RequestHandler
    {
       /*Redirects the client to the given URL for all GET requests.

        You should provide the keyword argument "url" to the handler, e.g.::

            application = web.Application([
                (r"/oldpath", web.RedirectHandler, {"url": "/newpath"}),
            ])
        */

        private string _url;
        private bool _permanent;

        public RedirectHandler(Application application_, HTTPRequest request_, Dictionary<string, object> kwargs)
            : base(application_, request_, kwargs)
        {
        }

        public override void initialize(Dictionary<string, object> kwargs)// string url, bool permanent=true)
        {
            //todo fix
            /*
            _url = (string)kwargs["url");
            _permanent = (bool)kwargs.get("permanent", true);*/
        }

        public override void get()
        {
            redirect(_url, _permanent);
        }
    }

    public class StaticFileHandler : RequestHandler
    {
        public StaticFileHandler(Application application_, HTTPRequest request_, Dictionary<string, object> kwargs)
            : base(application_, request_, kwargs)
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
        public CreateRequestHandler handler_class;
        public Dictionary<string,object> kwargs;
        public string name;

        //Specifies mappings between URLs and handlers.
        public URLSpec(string pattern, CreateRequestHandler handler_class_, Dictionary<string, object> kwargs_ = null, string name_ = null)
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
            kwargs = kwargs_ ?? new Dictionary<string,object>();
            name = name_;
            //todo _path, self._group_count = self._find_groups();
        }
    }
}


