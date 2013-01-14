using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;


namespace Tornado.httputil
{
    public class HTTPHeaders : Dictionary<string, string>
    {
        /*A dictionary that maintains Http-Header-Case for all keys.

        Supports multiple values per key via a pair of new methods,
        add() and get_list().  The regular dictionary interface returns a single
        value per key, with multiple values joined by a comma.

        >>> h = HTTPHeaders({"content-type": "text/html"})
        >>> h.keys()
        ['Content-Type']
        >>> h["Content-Type"]
        'text/html'

        >>> h.add("Set-Cookie", "A=B")
        >>> h.add("Set-Cookie", "C=D")
        >>> h["set-cookie"]
        'A=B,C=D'
        >>> h.get_list("set-cookie")
        ['A=B', 'C=D']

        >>> for (k,v) in sorted(h.get_all()):
        ...    print '%s: %s' % (k,v)
        ...
        Content-Type: text/html
        Set-Cookie: A=B
        Set-Cookie: C=D
        */

        private Dictionary<string, List<string>> _as_list;
        private string _last_key;

        public HTTPHeaders()
        {
            // Don't pass args or kwargs to dict.__init__, as it will bypass
            // our __setitem__
            _as_list = new Dictionary<string,List<string>>();
            _last_key = null;
            /*if (len(args) == 1 and len(kwargs) == 0 and
                isinstance(args[0], HTTPHeaders)):
                // Copy constructor
                for k, v in args[0].get_all():
                    add(k, v)
            else:
                // Dict-style initialization
                update(*args, **kwargs)*/
        }

        public void add(string name, string value)
        {
            // Adds a new value for the given key.
            var norm_name = HTTPHeaders._normalize_name(name);
            _last_key = norm_name;
            if (base.ContainsKey(norm_name))
            {
                // bypass our override of __setitem__ since it modifies _as_list
                //dict.__setitem__(self, norm_name, self[norm_name] + ',' + value)
                base[norm_name] = this[norm_name] + "," + value;

                _as_list[norm_name].Add(value);
            }
            else
                this[norm_name] = value; //todo check that this hits the override
        }

        public void parse_line(string line)
        {
            /*Updates the dictionary with a single header line.

            >>> h = HTTPHeaders()
            >>> h.parse_line("Content-Type: text/html")
            >>> h.get('content-type')
            'text/html'
            */
            if (line[0] == ' ')
            {
                // continuation of a multi-line header
                var new_part = ' ' + line.TrimStart(' ');
                _as_list[_last_key][-1] += new_part;
                //dict.__setitem__( _last_key, self[_last_key] + new_part)
                base[_last_key] = this[_last_key] + new_part;
            }
            else
            {
                var split = line.Split(new char[]{':'}, 2);
                string name = split[0], value = split[1];
                add(name, value.Trim());
            }
        }

        internal static HTTPHeaders parse(string headers)
        {
            /*Returns a dictionary from HTTP header text.

            >>> h = HTTPHeaders.parse("Content-Type: text/html\\r\\nContent-Length: 42\\r\\n")
            >>> sorted(h.iteritems())
            [('Content-Length', '42'), ('Content-Type', 'text/html')]
            */
            var h = new HTTPHeaders();
            foreach(var  line in headers.Split(new string[] { "\r\n",}, StringSplitOptions.None))
                if (!string.IsNullOrWhiteSpace(line))
                    h.parse_line(line);
            return h;
        }

        // dict implementation overrides

        public new string this[string name]
        {
            get 
            { 
                return base[HTTPHeaders._normalize_name(name)]; 
            }
            set
            {
                var norm_name = HTTPHeaders._normalize_name(name);
                base.Add(norm_name, value);
                _as_list[norm_name] = new List<string>() { value };
            }
        }

        public new void Add(string name, string value)
        {
            add(name, value);
        }

        public new void Remove(string name)
        {
            var norm_name = HTTPHeaders._normalize_name(name);
            base.Remove(name);
            _as_list.Remove(name);
        }

        public new bool ContainsKey(string name)
        {
            var norm_name = HTTPHeaders._normalize_name(name);
            return base.ContainsKey(norm_name);
        }

        public new bool TryGetValue(string name, out string value)
        {
            var norm_name = HTTPHeaders._normalize_name(name);

            return TryGetValue(norm_name, out value);
        }

        // remember get returns null if not found

        static Regex _NORMALIZED_HEADER_RE = new Regex("^[A-Z0-9][a-z0-9]*(-[A-Z0-9][a-z0-9]*)*$", RegexOptions.Compiled);
        static Dictionary<string, string> _normalized_headers = new Dictionary<string,string>();

        private static string _normalize_name(string name)
        {
            /*Converts a name to Http-Header-Case.

            >>> HTTPHeaders._normalize_name("coNtent-TYPE")
            'Content-Type'
            */
            try
            {
                return HTTPHeaders._normalized_headers[name];
            }
            catch(KeyNotFoundException ex)
            {
                var normalized = "";

                if (HTTPHeaders._NORMALIZED_HEADER_RE.IsMatch(name))
                    normalized = name;
                else
                    //normalized = "-".join([w.capitalize() for w in name.split("-")])
                    normalized = "-" + name.Split('-').Select(w => w.ToUpperInvariant());

                HTTPHeaders._normalized_headers[name] = normalized;
                return normalized;
            }
        }
    }

    public static class HttpUtil
    {
        public static void parse_body_arguments(string content_type, byte[] body, object arguments, object files)
        {
            /*Parses a form request body.

            Supports "application/x-www-form-urlencoded" and "multipart/form-data".
            The content_type parameter should be a string and body should be
            a byte string.  The arguments and files parameters are dictionaries
            that will be updated with the parsed contents.
            */
            //todo finish
            /*
            if (content_type.StartsWith("application/x-www-form-urlencoded"))
            {
                var uri_arguments = parse_qs_bytes(UTF8Encoding.UTF8.GetString(body));
                for name, values in uri_arguments.iteritems():
                    values = [v for v in values if v]
                    if values:
                        arguments.setdefault(name, []).extend(values)
            }
            else if (content_type.StartsWith("multipart/form-data"))
            {
                fields = content_type.split(";")
                for field in fields:
                    k, sep, v = field.strip().partition("=")
                    if k == "boundary" and v:
                        parse_multipart_form_data(utf8(v), body, arguments, files)
                        break
                else:
                    logging.warning("Invalid multipart/form-data")
            }*/
        }
    }
}
