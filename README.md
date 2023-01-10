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
 * Easily generate dynamic with simple handlers.
 * Serve static content from classpath resources or files.
 * Zero dependencies.
 * Basic HTTP authentication
 * WebSockets
 * Single source file. Can be just dropped into your project with ease.
 
### WIP

 * Cookie helpers.
 * Full JavaDoc.
 
### TODO

 * HTTP 2 and 3.
 * Cookie helpers.
 * Other authentication.
 * Lots of tests, testing and tuning.
 
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
 
Websockets. The `websocket()` builder has several methods for capturing events other than `onText()`, such as `onData()` for binary data.

The `send()` method sends text with automatic fragmentation, or the `fragment()` method can be used to send binary fragments.
 
 ```java
	try (var httpd = UHTTPD.server()
			.webSocket("/ws", UHTTPD.websocket().onText((txt, ws) -> {
				ws.send("Got '" + txt + "'");
			}).build())
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