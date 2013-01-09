
This is a faithful port of Facebook's Tornado Server to C#.

Faithful means the comments, order, files, and names of everything are as true to the original python code as possible.

This port was made for a few reasons.
	1. I like Tornado and use it in production already for locacha.com.
	2. I'd like to see what the performance and memory usage is like using C# as a base.
	3. IronPython does not create code that is easily linked to by other .Net projects.
	4. I have a program called Code Perspective that let's me see the state of a .Net app
		running on a remote server - I'd like to use this app explore Tornado.Net's architecture.
	5. The .Net community could benefit from an easy to use event based server.
