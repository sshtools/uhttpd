package com.sshtools.uhttpd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Semaphore;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.mizosoft.methanol.MediaType;
import com.github.mizosoft.methanol.Methanol;
import com.github.mizosoft.methanol.Methanol.Builder;
import com.github.mizosoft.methanol.MultipartBodyPublisher;
import com.github.mizosoft.methanol.MutableRequest;
import com.sshtools.uhttpd.UHTTPD.FormData;
import com.sshtools.uhttpd.UHTTPD.RootContextBuilder;
import com.sshtools.uhttpd.UHTTPD.Status;
import com.sshtools.uhttpd.UHTTPD.WebSocketBuilder;

public class UHTTPDTest {
	static String boundary = new BigInteger(256, new Random()).toString();
	
    @BeforeAll
    public static void beforeClass()
    {
		System.setProperty("java.util.logging.config.file", ClassLoader.getSystemResource("logging.properties").getPath());
		System.setProperty("jdk.httpclient.HttpClient.log", "errors,requests,headers,frames[:control:data:window:all],content,ssl,trace,channel,all");
		System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
//		System.setProperty("javax.net.debug", "ssl:all");
	}
	final Methanol client() {
		return clientBuilder().build();
	}
	
	final Builder clientBuilder() {
		Builder bldr = Methanol.newBuilder()
        .version(Version.HTTP_1_1)
        .followRedirects(Redirect.NORMAL);
		
		if(System.getProperty("uhttpd.test.timeouts", "true").equals("false")) {
		     bldr.connectTimeout(Duration.ofSeconds(30));
		     bldr.readTimeout(Duration.ofSeconds(30));
		}
		
		configureClient(bldr);
		
		return bldr;
//        .proxy(ProxySelector.of(new InetSocketAddress("proxy.example.com", 80)))
//        .authenticator(Authenticator.getDefault())
	}
	
	protected java.net.http.HttpClient.Builder configureClient(java.net.http.HttpClient.Builder builder) {
		return builder;
	}
	
	@Test
	void testWebsocketServerFirstMessage() throws Exception {
		var sem = new Semaphore(4);
		sem.acquire(4);
		try (var httpd = createServer().
		    webSocket("/ws", new WebSocketBuilder().
		    onText((txt, ws) -> {
				assertEquals("c-onText", txt);
		   		ws.send("s-onText");
		    	sem.release();
		    }).
		    onClose((code, text, ws) -> {
		    }).
		    onOpen((ws) -> {
		    	sem.release();
		   		ws.send("s-onOpen");
		    }).
		    build()).
		    classpathResources("(.*)", "web").
		    build()) {
			
			httpd.start();
			
			try {
				// open websocket
				var ws = configureClient(HttpClient.newBuilder()).build().newWebSocketBuilder().buildAsync(URI.create(wsClientURL() + "/ws"), new Listener() {

					private boolean sentOne;

					@Override
					public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
						var txt = data.toString();
						if(sentOne) {
							assertEquals("s-onText", txt);
						}
						else {
							assertEquals("s-onOpen", txt);
							webSocket.sendText("c-onText", true);
							sentOne = true;
						}
				    	sem.release();
						return Listener.super.onText(webSocket, data, last);
					}
					
				}).get();

				sem.acquire();
				sem.release();
				

			} catch (InterruptedException ex) {
				System.err.println("InterruptedException exception: " + ex.getMessage());
			} 
		} 
	}

	@Test
	void testSendCookie() throws Exception {
		var mgr = new CookieManager();
		var num = (int)(Math.random() * 1000);
		try(var httpd = createServer().
			get("/cookies\\.html", (tx) -> {
				var cookie = tx.cookie("mycookie");
				assertEquals("cookie" + num, cookie.value());
			}).
			build()) {
			httpd.start();
			
			//			
			var sessionCookie = new HttpCookie("mycookie", "cookie" + num);
	        sessionCookie.setPath("/");
	        sessionCookie.setVersion(0);
	        mgr.getCookieStore().add(URI.create(clientURL()), sessionCookie);
	        
		        
			var client = clientBuilder().cookieHandler(mgr).build();
			var req = HttpRequest.newBuilder().uri(URI.create(clientURL() + "/cookies.html")).GET().build();
			var resp = client.send(req, BodyHandlers.ofString());
			assertEquals(Status.OK.getCode(), resp.statusCode());
		}
	}

	@Test
	void testGetBigString() throws Exception {
		var strbuf = new StringBuilder();
		for(int i = 0 ; i < 20000; i ++) {
			strbuf.append("0123456789");
		}
		try(var httpd = createServer().
			get("/big\\.html", (tx) -> {
				tx.response(strbuf.toString());
			}).
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().uri(URI.create(clientURL() + "/big.html?a=1&b=2")).GET().build();
			var resp = client.send(req, BodyHandlers.ofString());
			assertEquals(strbuf.toString(), resp.body());
		}
	}

	@Test
	void testGet() throws Exception {
		try(var httpd = createServer().
			get("/calc\\.html", (tx) -> {
				tx.response(MessageFormat.format("{0} + {1} = {2}", 
						tx.parameter("a").asString(), 
						tx.parameter("b").asString(),
						tx.parameter("a").asFloat() + tx.parameter("b").asFloat()));
			}).
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().uri(URI.create(clientURL() + "/calc.html?a=1&b=2")).GET().build();
			var resp = client.send(req, BodyHandlers.ofString());
			assertEquals("1 + 2 = 3", resp.body());
		}
	}

	@Test
	void testGetFileNoCompressNotChunked() throws Exception {
		var tf = createTempDataFile(10000);
		try(var httpd = createServer().
			get("/get", (tx) -> {
				tx.response(tf);
			}).
			withoutCompression().
			withMaxUnchunkedSize(10000 * 2). // twice size of file
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().
					uri(URI.create(clientURL() + "/get")).
					GET().
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));
				assertNotEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).orElse(""));
				assertNotEquals("chunked", resp.headers().firstValue(UHTTPD.HDR_TRANSFER_ENCODING).orElse(""));
				assertTrue(isEqual(tf, outf));
			}
			finally {
				Files.delete(outf);
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	@Test
	void testGetFileNoCompressChunked() throws Exception {
		var tf = createTempDataFile(10000);
		try(var httpd = createServer().
			get("/get", (tx) -> {
				tx.response(Files.newInputStream(tf)); // using a stream stops content length being automatically added
			}).
			withoutCompression().
			withMaxUnchunkedSize(10000 / 2). // half size of file
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().
					uri(URI.create(clientURL() + "/get")).
					GET().
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));
				assertNotEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).orElse(""));
				assertEquals("chunked", resp.headers().firstValue(UHTTPD.HDR_TRANSFER_ENCODING).orElse(""));
				assertTrue(isEqual(tf, outf));
			}
			finally {
				Files.delete(outf);
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	@Test
	void testGetFileGzipNotChunked() throws Exception {
		var tf = createCompressableTempDataFile(10000);
		try(var httpd = createServer().
			get("/get", (tx) -> {
				tx.response(tf); // can use file here, as compression prevents content length being automatically determined
			}).
			withMaxUnchunkedSize(10000 * 2). // twice size of file will mean gzipped content is buffered
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req =  MutableRequest.GET(clientURL() + "/get").
					header(UHTTPD.HDR_ACCEPT_ENCODING, "gzip").
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));
				// TODO Methanol seems to strip these headers (i presume because content returned to client code wont be compressed). Not sure how we'd test this
//				assertEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).get());
				assertTrue(isEqual(tf, outf));
			}
			finally {
				Files.delete(outf);
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	@Test
	void testGetFileGzipChunked() throws Exception {
		var tf = createCompressableTempDataFile(10000);
		try(var httpd = createServer().
			get("/get", (tx) -> {
				tx.response(tf); // can use file here, as compression prevents content length being automatically determined
			}).
			withMaxUnchunkedSize(10000 / 2). // half size of file will mean gzipped content is chunked
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req =  MutableRequest.GET(clientURL() + "/get").
					header(UHTTPD.HDR_ACCEPT_ENCODING, "gzip").
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));

				// TODO Methanol seems to strip these headers (i presume because content returned to client code wont be compressed). Not sure how we'd test this
//				assertEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).get());
				assertTrue(isEqual(tf, outf));
			}
			finally {
				Files.delete(outf);
			}
		}
		finally {
			Files.delete(tf);
		}
	}
//	@Test
//	void testGetConditional() throws Exception {
//		var tf = createTempDataFile(10000);
//		try(var httpd = createServer().
//			get("/get", (tx) -> {
//				tx.response(tf); // can use file here, as compression prevents content length being automatically determined
//			}).
//			withMaxUnchunkedSize(10000 / 2). // half size of file will mean gzipped content is chunked
//			build()) {
//			httpd.start();
//			XXXX
//			//			
//			var client = client();
//			var req =  MutableRequest.GET(clientURL() + "/get").
//					header(UHTTPD.HDR_ACCEPT_ENCODING, "gzip").
//					build();
//			var outf = Files.createTempFile("http", "data");
//			try {
//				var resp = client.send(req, BodyHandlers.ofFile(outf));
//
//				// TODO Methanol seems to strip these headers (i presume because content returned to client code wont be compressed). Not sure how we'd test this
////				assertEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).get());
//				assertTrue(isEqual(tf, outf));
//			}
//			finally {
//				Files.delete(outf);
//			}
//		}
//		finally {
//			Files.delete(tf);
//		}
//	}

	@Test
	void testPostFormUrlEncoded() throws Exception {
		try(var httpd = createServer().
			post("/order\\.html", (tx) -> {
				var content = tx.request();
				var name = content.asNamed("name").asString();
				var items = content.asNamed("items").asInt();
				var country = content.asNamed("address").asString();
				tx.response("Order 12356 for " + name + " in "  + country  +" has " + items + " items");
			}).
			build()) {
			httpd.start();
			
			//
			var client = client();
			var req = HttpRequest.newBuilder().
					uri(URI.create(clientURL() + "/order.html")).
					header("Content-Type", "application/x-www-form-urlencoded").
					POST(ofNameValuePairs(
							"name", "Joe Bloggs", 
							"address", "The Moon", 
							"items", "987")).
					build();
			var resp = client.send(req, BodyHandlers.ofString());
			assertEquals("Order 12356 for Joe Bloggs in The Moon has 987 items", resp.body());
		}
	}

	@Test
	void testPostFile() throws Exception {
		
		var tf = createTempDataFile(10000);
		try {
			
			try(var httpd = createServer().
				post("/upload", (tx) -> {
					var content = tx.request();
					assertEquals("application/octet-stream", content.contentType().orElseThrow());
					try(var in = content.asChannel()) {
						try(var other = Files.newByteChannel(tf)) {
							assertTrue(isEqual(in, other));
						}
					}
					tx.responseCode(Status.OK);
				}).
				build()) {
				httpd.start();
				
				//
				var client = client();
				var req = HttpRequest.newBuilder().
						uri(URI.create(clientURL() + "/upload")).
						header("Content-Type", "application/octet-stream").
						POST(BodyPublishers.ofFile(tf)).
						build();
				var resp = client.send(req, BodyHandlers.ofString());
				assertEquals(Status.OK.getCode(), resp.statusCode());
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	@Test
	void testMultipart() throws Exception {
		
		var tf = createTempDataFile(10);
		var halfBoundary = "--" + boundary.substring(0, boundary.length() / 2);
		var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		
		var sr = new SecureRandom();
		var lval = sr.nextLong();
		var sval = (short)sr.nextInt();
		var ival = sr.nextInt();
		var bval = (byte)sr.nextInt();
		var cval = (char)sr.nextInt();
		var dval = sr.nextDouble();
		var fval = sr.nextFloat();
		var aval = sr.nextBoolean();
		try {
			
			try(var httpd = createServer().
				post("/upload", (tx) -> {
					var content = tx.request();
					int parts = 0;
					for(var part : content.asParts(FormData.class)) {
						switch(part.name()) {
						case "file":
							try(var in = part.asChannel()) {
								try(var other = Files.newByteChannel(tf)) {
									assertTrue(isEqual(in, other));
								}
							}
							break;
						case "name":
							assertEquals("A Name", part.asString());
							break;
						case "email":
							assertEquals("An Email", part.asString());
							break;
						case "halfboundary":
							assertEquals(halfBoundary, part.asString());
							break;
						case "lval":
							assertEquals(lval, part.asLong());
							break;
						case "sval":
							assertEquals(sval, part.asShort());
							break;
						case "ival":
							assertEquals(ival, part.asInt());
							break;
						case "bval":
							assertEquals(bval, part.asByte());
							break;
						case "cval":
							assertEquals(cval, part.asChar());
							break;
						case "dval":
							assertEquals(dval, part.asDouble());
							break;
						case "fval":
							assertEquals(fval, part.asFloat());
							break;
						case "aval":
							assertEquals(aval, part.asBoolean());
							break;
						case "now":
							assertEquals(now, part.asInstant());
							break;
						case "filename":
							assertEquals(tf.getFileName().toString(), part.asString());
							break;
						default:
							throw new IllegalStateException("Unexpected part " + part.name());
						
						}
						parts++;
					}
					
					assertEquals(14, parts);
				}).
				build()) {
				httpd.start();
				
				//
				var client = client();
				
				var multipartBody = MultipartBodyPublisher.newBuilder()
					      .filePart("file", tf, MediaType.APPLICATION_OCTET_STREAM)
					      .textPart("name", "A Name")
					      .textPart("email", "An Email")
					      .textPart("halfboundary", halfBoundary)
					      .textPart("lval", lval)
					      .textPart("sval", sval)
					      .textPart("ival", ival)
					      .textPart("bval", bval)
					      .textPart("cval", cval)
					      .textPart("dval", dval)
					      .textPart("fval", fval)
					      .textPart("aval", aval)
					      .textPart("now", UHTTPD.formatInstant(now))
					      .textPart("filename", tf.getFileName().toString())
					      .build();
				
				
				var req = HttpRequest.newBuilder().
						uri(URI.create(clientURL() + "/upload")).
						header("Content-Type", "multipart/form-data;boundary=" + boundary).
						POST(multipartBody).
						build();
				var resp = client.send(req, BodyHandlers.ofString());
				System.err.println("GOT RESP " + resp.body());
				assertEquals(Status.OK.getCode(), resp.statusCode());
				System.err.println("DONE");
			}
		}
		finally {
			Files.delete(tf);
		}
	}
	
	@Test
	void testMultipartMisorderedAccess() throws Exception {
		
		var tf = createTempDataFile(10);
		var halfBoundary = "--" + boundary.substring(0, boundary.length() / 2);
		try {
			
			try(var httpd = createServer().
				post("/upload", (tx) -> {
					var content = tx.request();

					try {
					assertEquals(tf.getFileName().toString(), content.asFormData("filename").asString());
					var ref = content.asFormData("reference");
					var refStr = ref.asString();
					assertEquals("A Description", refStr);
					assertEquals(halfBoundary, content.asFormData("halfboundary").asString());
					assertEquals("An Email", content.asFormData("email").asString());
					assertEquals("A Name", content.asFormData("name").asString());
					}
					catch(Exception e) {
						e.printStackTrace();
					}
				}).
				build()) {
				httpd.start();
				
				//
				var client = client();
				
				var multipartBody = MultipartBodyPublisher.newBuilder()
					      .filePart("file", tf, MediaType.APPLICATION_OCTET_STREAM)
					      .textPart("name", "A Name")
					      .textPart("email", "An Email")
					      .textPart("halfboundary", halfBoundary)
					      .textPart("reference", "A Description")
					      .textPart("filename", tf.getFileName().toString())
					      .build();
				
				
				var req = HttpRequest.newBuilder().
						uri(URI.create(clientURL() + "/upload")).
						header("Content-Type", "multipart/form-data;boundary=" + boundary).
						POST(multipartBody).
						build();
				var resp = client.send(req, BodyHandlers.ofString());
				System.err.println("GOT RESP " + resp.body());
				assertEquals(Status.OK.getCode(), resp.statusCode());
				System.err.println("DONE");
			}
		}
		finally {
			Files.delete(tf);
		}
	}
	
	@Test
	void testMultipartIncompleteAccess() throws Exception {
		
		var tf = createTempDataFile(10);
		var halfBoundary = "--" + boundary.substring(0, boundary.length() / 2);
		try {
			
			try(var httpd = createServer().
				post("/upload", (tx) -> {
					var content = tx.request();
					assertEquals("An Email", content.asFormData("email").asString());
				}).
				build()) {
				httpd.start();
				
				//
				var client = client();
				
				var multipartBody = MultipartBodyPublisher.newBuilder()
					      .filePart("file", tf, MediaType.APPLICATION_OCTET_STREAM)
					      .textPart("name", "A Name")
					      .textPart("email", "An Email")
					      .textPart("halfboundary", halfBoundary)
					      .textPart("reference", "A Description")
					      .textPart("filename", tf.getFileName().toString())
					      .build();
				
				
				var req = HttpRequest.newBuilder().
						uri(URI.create(clientURL() + "/upload")).
						header("Content-Type", "multipart/form-data;boundary=" + boundary).
						POST(multipartBody).
						build();
				var resp = client.send(req, BodyHandlers.ofString());
				System.err.println("GOT RESP " + resp.body());
				assertEquals(Status.OK.getCode(), resp.statusCode());
				System.err.println("DONE");
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	protected RootContextBuilder createServer() {
		return UHTTPD.server().withoutHttps().withHttp(58080);
	}
	
	protected String wsClientURL() {
		return "ws://localhost:58080";
	}
	
	protected String clientURL() {
		return "http://localhost:58080";
	}

	static Path createTempDataFile(long size) throws IOException {
		var sn = new SecureRandom();
		var tf = Files.createTempFile("random", ".data");
		try(var out = Files.newOutputStream(tf)) {
			for(int i = 0 ; i < size; i++) {
				out.write(sn.nextInt(256));
			}
		}
		return tf;
	}

	static Path createCompressableTempDataFile(long size) throws IOException {
		var sn = new SecureRandom();
		var tf = Files.createTempFile("random", ".data");
		try(var out = Files.newOutputStream(tf)) {
			for(int i = 0 ; i < size; i++) {
				if(i < size / 2)
					out.write(sn.nextInt(256));
				else
					out.write(0);
			}
		}
		return tf;
	}

	static HttpRequest.BodyPublisher ofNameValuePairs(String... parms) {
		if(parms.length %2 != 0)
			throw new IllegalArgumentException("Must be pairs.");
		var b = new StringBuilder();
		for (int i = 0 ; i < parms.length ; i += 2) {
			if (b.length() > 0) {
				b.append("&");
			}
			b.append(URLEncoder.encode(parms[i], StandardCharsets.UTF_8));
			if (parms[i + 1] != null) {
				b.append('=');
				b.append(URLEncoder.encode(parms[i + 1], StandardCharsets.UTF_8));
			}
		}
		return HttpRequest.BodyPublishers.ofString(b.toString());
	} 

	private static boolean isEqual(Path p1, Path p2) throws IOException {
		try(var i1 = Files.newInputStream(p1)) {
			try(var i2 = Files.newInputStream(p2)) {
				return isEqual(i1, i2);
			}	
		}
	}

	private static boolean isEqual(InputStream i1, InputStream i2) throws IOException {
	    var ch1 = Channels.newChannel(i1);
	    var ch2 = Channels.newChannel(i2);		
	    return isEqual(ch1, ch2);
	}
	
	private static boolean isEqual(ReadableByteChannel ch1, ReadableByteChannel ch2)
	        throws IOException {


	    var buf1 = ByteBuffer.allocateDirect(1024);
	    var buf2 = ByteBuffer.allocateDirect(1024);

        while (true) {

            int n1 = ch1.read(buf1);
            int n2 = ch2.read(buf2);

            if (n1 == -1 || n2 == -1) return n1 == n2;

            buf1.flip();
            buf2.flip();

            for (int i = 0; i < Math.min(n1, n2); i++)
                if (buf1.get() != buf2.get())
                    return false;

            buf1.compact();
            buf2.compact();
        }
	}

}
