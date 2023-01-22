package com.sshtools.uhttpd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.mizosoft.methanol.MediaType;
import com.github.mizosoft.methanol.Methanol;
import com.github.mizosoft.methanol.MultipartBodyPublisher;
import com.github.mizosoft.methanol.MutableRequest;
import com.sshtools.uhttpd.UHTTPD.FormData;
import com.sshtools.uhttpd.UHTTPD.Status;

public class UHTTPDTest {
	static String boundary = new BigInteger(256, new Random()).toString();
	
    @BeforeAll
    public static void beforeClass()
    {
		System.setProperty("java.util.logging.config.file", ClassLoader.getSystemResource("logging.properties").getPath());
		System.setProperty("jdk.httpclient.HttpClient.log", "errors,requests,headers,frames[:control:data:window:all],content,ssl,trace,channel,all");
	}
	
	Methanol client() {
		return Methanol.newBuilder()
        .version(Version.HTTP_1_1)
        .followRedirects(Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(20))
//        .proxy(ProxySelector.of(new InetSocketAddress("proxy.example.com", 80)))
//        .authenticator(Authenticator.getDefault())
        .build();
	}

	@Test
	void testGet() throws Exception {
		try(var httpd = UHTTPD.server().
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
			var req = HttpRequest.newBuilder().uri(URI.create("http://localhost:8080/calc.html?a=1&b=2")).GET().build();
			var resp = client.send(req, BodyHandlers.ofString());
			assertEquals("1 + 2 = 3", resp.body());
		}
	}

	@Test
	void testGetFileNoCompress() throws Exception {
		var tf = createTempDataFile(10000);
		try(var httpd = UHTTPD.server().
			get("/get", (tx) -> {
				tx.response(tf);
			}).
			withoutCompression().
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().
					uri(URI.create("http://localhost:8080/get")).
					GET().
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));
				assertNotEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).orElse(""));
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
		try(var httpd = UHTTPD.server().
			get("/get", (tx) -> {
				tx.response(Files.newInputStream(tf));
			}).
			withoutCompression().
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req = HttpRequest.newBuilder().
					uri(URI.create("http://localhost:8080/get")).
					header(UHTTPD.HDR_ACCEPT_ENCODING, "identity").
					GET().
					build();
			var outf = Files.createTempFile("http", "data");
			var resp = client.send(req, BodyHandlers.ofFile(outf));
			assertNotEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).orElse(""));
			try {
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
	void testGetFileGzip() throws Exception {
		var tf = createCompressableTempDataFile(10000);
		try(var httpd = UHTTPD.server().
			get("/get", (tx) -> {
				tx.response(tf);
			}).
			
			build()) {
			httpd.start();
			
			//			
			var client = client();
			var req =  MutableRequest.GET("http://localhost:8080/get").
//					header(UHTTPD.HDR_ACCEPT_ENCODING, "gzip").
					build();
			var outf = Files.createTempFile("http", "data");
			try {
				var resp = client.send(req, BodyHandlers.ofFile(outf));
				assertEquals("gzip", resp.headers().firstValue(UHTTPD.HDR_CONTENT_ENCODING).get());
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
	void testPostFormUrlEncoded() throws Exception {
		try(var httpd = UHTTPD.server().
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
					uri(URI.create("http://localhost:8080/order.html")).
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
			
			try(var httpd = UHTTPD.server().
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
						uri(URI.create("http://localhost:8080/upload")).
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
		try {
			
			try(var httpd = UHTTPD.server().
				post("/upload", (tx) -> {
					var content = tx.request();
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
						case "reference":
							assertEquals("A Description", part.asString());
							break;
						case "filename":
							assertEquals(tf.getFileName().toString(), part.asString());
							break;
						default:
							throw new IllegalStateException("Unexpected part " + part.name());
						
						}
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
						uri(URI.create("http://localhost:8080/upload")).
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
