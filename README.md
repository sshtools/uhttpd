# µHTTPD

A very small HTTP/HTTPS server, intended for embedding into other applications generating dynamic content.

**This is not yet intended for production use. But may be useful in very simple projects or testing and development.** 

## Quick Start

```java

public class SimpleServer {
	public static void main(String[] args) throws Exception {
		try(var httpd = UHTTPD.server().
			get("/index\\.txt", (tx) -> tx.response("Hello World!")).
			build()); {
			httpd.run();
		}
	}
}
```

This will run a server in the foreground on `localhost:8080`. Point your browser to [http://localhost:8080/index.txt](http://localhost:8080/index.txt)

## About

### Features

 * Supports HTTP and HTTPS (HTTP/1.0 and HTTP/1.1).
 * Easily generate dynamic content with simple handlers.
 * Serve static content from classpath resources or files.
 * Zero dependencies.
 * Basic HTTP authentication.
 * WebSockets.
 * Single source file. Can be just dropped into your project with ease.
 * Cookies.
 
### WIP

 * Full JavaDoc.
 
### TODO

 * Chunking
 * CONNECT
 * HTTP 2 and 3.
 * Other authentication.
 * Lots of tests, testing and tuning.
 * Replace threads with [fibers](https://www.infoworld.com/article/3652596/project-loom-understand-the-new-java-concurrency-model.html).
 
### Anti Features

 * It will not support the servlet spec (although an extension could).
 * It will not support non-programmatic configuration (although an extension could).
 * It will not allow configuration change at runtime.
 * It will not use non-blocking IO or any other framework based on it. 

## More Examples
 
Serving some HTML.
 
 ```java
try(var httpd = UHTTPD.server().
	get("/index\\.html", (tx) -> { 
		tx.response("text/html", """
		<html>
		<body>
		<p>Click <a href="other.html">here</a> to go to another page</p>
		</body>
		</html>
		"""); 
	}).
	get("/other\\.html", (tx) -> { 
		tx.response("text/html", """
		<html>
		<body>
		<p>Click <a href="other.html">here</a> to go back to the home page</p>
		</body>
		</html>
		"""); 
	}).
	build()) {
	httpd.run();
}
 ``` 
 
Handling `GET` parameters.
 
 ```java
try(var httpd = UHTTPD.server().
	get("/calc\\.html", (tx) -> {
		tx.response(MessageFormat.format("{0} + {1} = {2}", 
				tx.parameter("a").asString(), 
				tx.parameter("b").asString(),
				tx.parameter("a").asFloat() + tx.parameter("b").asFloat()));
	}).
	build()) {
	httpd.run();
}
 ```
 
Handling `POST` parameters, e.g. file upload.
 
 ```java
 try(var httpd = UHTTPD.server().
	get("/upload", (tx) -> {
		var content = tx.request();
		var tmpFile = Files.createTempFile("upload", ".test");
		var file = content.asFormData("file");
		try(var in = file.asStream()) {
			try(var out = Files.newOutputStream(tmpFile)) {
				in.transferTo(out);
			}
		}
		req.response(MessageFormat.format("Uploaded to {0} (Content type: {1})", tmpFile, file.contentType().orElse("Unknown")));
	}).
	build()) {
	httpd.run();
}
 ```
 
Using a `Responder` to feed response content.
 
 ```java
try(var httpd = UHTTPD.server().
	get("/respond", (tx) -> {
		var line = new AtomicInteger(0);
		tx.responder(buf -> {
			if(line.incrementAndGet() < 10) {
				buf.put(ByteBuffer.wrap(("Line " + line.get() + "\n").getBytes()));
			}
		});
	}).
	build()) {
	httpd.run();
}
 ```
 
Adding authentication (HTTP Basic) to some pages.
 
 ```java
try(var httpd = UHTTPD.server().
	get("/login\\.html", 
		(tx) -> { 
			tx.response("text/html", """
			<html>
			<body>
			<p>Click <a href="protected.html">here</a> to login to protected page.</p>
			<p>The username is <bold>user</bold> and the password is <bold>password</bold>
			</body>
			</html>
			"""); 
	}).
	get("/protected\\.html",
			
		UHTTPD.httpBasicAuthentication((creds) -> 
				creds.result(
					creds.username().equals("user") && 
					new String(creds.password()).equals("password")))
				.withRealm("MyRealm")).build(),
				
		(tx) -> { 
			tx.response("text/html", """
			<html>
			<body>
			<p>This is a protected page.</p>
			</body>
			</html>
			"""); 
	}).
	build()) {
	httpd.run();
}
 ```
 
Serve static files and classpath resources. The matching pattern usings regular expression capture groups. 
 
 ```java
 try(var httpd = UHTTPD.server().
	withClasspathResources("/cp/(.*)", "web").
	withFileResources("/local/(.*)", Paths.get("/home/auser/share")).
	build()) {
	httpd.run();
}
 ```
 
Cookies.

```java
try (var httpd = UHTTPD.server().get("/set-cookie\\.html", (tx) -> {
	tx.cookie(UHTTPD.cookie("MyCookie", "A Value").build());
	tx.response("text/html", """
			<html>
			<body>
			<p>I have set a cookie!</p>
			</body>
			</html>
			""");
}).get("/get-cookie\\.html", (tx) -> {
	tx.response("text/html", """
			<html>
			<body>
			<p>The cookie value is __cookie__.</p>
			</body>
			</html>
			""".replace("__cookie__", tx.cookie("MyCookie").value()));
}).build()) {
	httpd.run();
}
```


Websockets. 

 ```java
try (var httpd = UHTTPD.server()
	.webSocket("/ws", UHTTPD.websocket().
		onText((txt, ws) -> {
		
			System.out.println("got '" + txt + "'");
		
			ws.send("I received '" + txt + "'"); // text reply
		}).
		onData((buf, fin, ws) -> {
			System.out.println("got " + buf.remaining() + " bytes");
		
			ws.send(ByteBuffer.wrap(new byte[] {1,2,3})); // single binary reply
			
			ws.fragment(ByteBuffer.wrap(new byte[] {1}), false); // 1st fragment
			ws.fragment(ByteBuffer.wrap(new byte[] {2}), false); // 2nd fragment
			ws.fragment(ByteBuffer.wrap(new byte[] {3}), true); // final fragment
		}).
		onClose((code, text, ws) -> {
			// web socket closed
		}).
		onOpen((ws) -> {
			ws.send("Hello!");
		}).
		build())
	.withClasspathResources("(.*)", "web")
	.build()) {
	httpd.run();
} 
 ```
 
Running the server in the background.
 
 ```java
 var builder = UTTPD.server();
 
 builder.withFileResources("/local/(.*)", Paths.get("/home/auser/share"));
 builder.withHttp(8081);
 
 var server = builder.build();
 server.start(); // starts in background
 
 // ...
 // do other stuff 
 // ...
 
 server.close();
 server.join(); // optionally wait for threads to shutdown
 
 ```