using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Tornado;
using Tornado.httpserver;
using Tornado.ioloop;
using Tornado.web;


namespace DemoServer
{
    class MainHandler : RequestHandler
    {
        public void get()
        {
            write("Hello, world");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var application = new Application(new TupleList<string, Func<RequestHandler>, Dictionary<string, string>> {
                {"/", () => new MainHandler(), null}});

            var http_server = new HTTPServer(application.Call);
            http_server.listen(8888);
            IOLoop.instance().start();
        }
    }
}
