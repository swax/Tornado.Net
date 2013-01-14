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
        public MainHandler(Application application_, HTTPRequest request_, Dictionary<string, object> kwargs)
            : base(application_, request_, kwargs)
        {
        }

        public override void get()
        {
            write(UTF8Encoding.UTF8.GetBytes("Hello, world again"));
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var application = new Application(new TupleList<string, CreateRequestHandler, Dictionary<string, object>> {
                {"/", (app, req, args_) => new MainHandler(app, req, args_), null}});

            var http_server = new HTTPServer(application.Call);
            http_server.listen(8888);
            IOLoop.instance().start();
        }
    }
}
