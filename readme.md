## Tornado.Net

This is a faithful port of Facebook's Tornado Server to C#.

Faithful means the comments, order, files, and names of everything are as true to the original python code as possible.

This port was made for a few reasons.

1. I like Tornado and use it in production already for [locacha.com](http://www.locacha.com).
2. I'd like to see what the performance and memory usage is like using C# as a base.
3. IronPython does not create code that is easily linked to by other .Net projects.
4. I have a program called [Code Perspective](https://www.codeperspective.com) that let's me visually inspect the state of a .Net app running on a remote server - I'd like to use this app to explore Tornado's architecture.
5. The .Net community could benefit from an easy to use event based server on windows and linux.

## Status

Most of the backend httpserver, iostream, and ioloop is working. Currently the web framework is being ported so connections are routed properly.
