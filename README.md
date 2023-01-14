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
 * CONNECT tunnels.
 * Multiple contexts.
 * Can work with [fibers](https://www.infoworld.com/article/3652596/project-loom-understand-the-new-java-concurrency-model.html).
 
### WIP

 * Full JavaDoc.
 * Compression (content and websocket extension).
 * Chunking (output done).
 
### TODO

 * Character sets.
 * HTTP 2 and 3.
 * Other authentication.
 * Lots of tests, testing and tuning.
 
### Anti Features

 * It will not support the servlet spec (although an extension could).
 * It will not support non-programmatic configuration (although an extension could).
 * It will not allow configuration change at runtime.
 * It will not use non-blocking IO framework. 

## More Examples

Simple examples. Most will start the server in the foreground indefinitely.

 * [Serving some HTML](#serving-some-html)
 * [Handling `GET` parameters](#handling-get-parameters)
 * [Handling `POST` parameters](#handling-post-parameters)
 * [Responder](#responder)
 * [Contexts](#contexts)
 * [Authentication](#authentication)
 * [Static Content](#static-content)
 * [Cookies](#cookies)
 * [WebSockets](#websockets)
 * [Tunnels](#tunnels)
 * [Error Pages](#error-pages)
 * [SSL](#ssl) 
 * [Using Fibers](#using-fibers) 
 * [Running In Background](#running-in-background)
 
### Serving some HTML
 
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
 
### Handling `GET` parameters
 
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
 
### Handling `POST` parameters

For example, file uploads.
 
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

### Responder

Use a `responder()` to feed response content chunk by chunk.
 
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
 
### Contexts

Contexts let you isolate and group any `Handler` under a single path. Any paths of the contained handlers are then relative to the context path. Contexts can be nested. 

Contexts are themselves a `Handler`, so can be added with a `HandlerSelector`, or preceeded by authentication handlers etc. 
 
```java
try(var httpd = UHTTPD.server().
	context(UHTTPD.context("/others/(.*)").
		get("/file.txt", tx -> tx.response("Some more text.")).
		get("/file2.txt", tx -> tx.response("More other text.")).
		build()).
	get("/file.txt", tx -> tx.response("Some text")).
	get("/file2.txt", tx -> tx.response("Other text")).
	withHttps().
	build()) {
	httpd.run();
}
```
### Authentication

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
 
### Static Content

Serve static files and classpath resources. The matching pattern usings regular expression capture groups. 
 
 ```java
 try(var httpd = UHTTPD.server().
	classpathResources("/cp/(.*)", "web").
	fileResources("/local/(.*)", Paths.get("/home/auser/share")).
	build()) {
	httpd.run();
}
 ```

### Cookies
 
Receiving cookie string values and responding with `Cookie` objects.

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

### WebSockets

Send and receive text and binary messages. 

 ```java
try (var httpd = UHTTPD.server()
	.webSocket("/ws", UHTTPD.webSocket().
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
	.classpathResources("(.*)", "web")
	.build()) {
	httpd.run();
} 
 ```
 
### Tunnels

Tunnelling using the `CONNECT` header. This directly connects a new Socket. You can optionally use `UHTTPD.tunnel()` which returns a `TunnelBuilder` which allows you to handle the incoming and outgoing data yourself.  
 
 ```java
 try(var httpd = UHTTPD.server().tunnel(UHTTPD.socketTunnel()).build()) {
	httpd.run();
}
 ```

### Error Pages

Setting error pages. You can set a handler that is invoked when a particular status code occurs.

```java
try(var httpd = UHTTPD.server().	
	status(Status.NOT_FOUND, UHTTPD.classpathResource("web/404.html")).build()) {
	httpd.run();
}
```

### SSL

To use SSL you must provide a `KeyStore`. If you don't specifically supply one, there must a keystore file at `$HOME/.keystore` with a passphrase of `changeit` (this is the default used by the `keytool` command). Otherwise, either provide the path to a keystore file along with passwords, or provide an instance of `KeyStore`. The default port for SSL is 8443.


```java
try(var httpd = UHTTPD.server().
	get("/text.txt", tx -> {
		tx.response("text/plain", "This is some text.");
	}).
	withHttps().
	build()) {
	httpd.run();
}
```

To generate a self signed certificate for development use, run `keytool`. 

```
keytool -genkey -alias uhttpd -keyalg RSA
```

### Using Fibers

If you hava Java 19 and use the `--enable-preview` argument to both compile and run, you can try out the use of [fibers](https://www.infoworld.com/article/3652596/project-loom-understand-the-new-java-concurrency-model.html). These are lightweight threads that should greatly increase scalability. Once the feature is enabled, simply set a custom `Runner`.

```java
try(var httpd = server().
	get("/file.txt", tx -> tx.response(Paths.get("/home/tanktarta/Desktop/SMS and EMAIL API Example.java"))).
	withRunner(r -> Thread.startVirtualThread(r)).
	build()) {
	httpd.run();
}
```

### Running In Background
 
Running the server in the background.
 
```java
var builder = UTTPD.server();
 
builder.fileResources("/local/(.*)", Paths.get("/home/auser/share"));
builder.withHttp(8081);
 
var server = builder.build();
server.start(); // starts in background
 
// ...
// do other stuff 
// ...
 
server.close();
server.join(); // optionally wait for threads to shutdown
```
