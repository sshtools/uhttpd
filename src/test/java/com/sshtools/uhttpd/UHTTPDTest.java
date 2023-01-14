package com.sshtools.uhttpd;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Duration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.sshtools.uhttpd.UHTTPD.Status;

public class UHTTPDTest {
	
	HttpClient client() {
		return HttpClient.newBuilder()
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
			var client = client();
			var req = HttpRequest.newBuilder().uri(URI.create("http://localhost:8080/calc.html?a=1&b=2")).GET().build();
			var resp = client.send(req, BodyHandlers.ofString());
			Assertions.assertEquals("1 + 2 = 3", resp.body());
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
			Assertions.assertEquals("Order 12356 for Joe Bloggs in The Moon has 987 items", resp.body());
		}
	}

	@Test
	void testPostFile() throws Exception {
		
		var tf = createTempDataFile();
		try {
			
			try(var httpd = UHTTPD.server().
				post("/upload", (tx) -> {
					var in = tx.request().asStream();
					var read = 0;
					try(var sourceIn = Files.newInputStream(tf)) {
						while(true) {
							var r = sourceIn.read();
							if(r == -1)
								break;
							var rr = in.read();
							if(r == -1 || r != rr)
								break;
							read++;
						}
					}
					tx.responseCode(read == 10000 ? Status.OK : Status.BAD_REQUEST);
				}).
				build()) {
				httpd.start();
				var client = client();
				var req = HttpRequest.newBuilder().
						uri(URI.create("http://localhost:8080/upload")).
						header("Content-Type", "application/octet-stream").
						POST(BodyPublishers.ofFile(tf)).
						build();
				var resp = client.send(req, BodyHandlers.ofString());
				Assertions.assertEquals(200, resp.statusCode());
			}
		}
		finally {
			Files.delete(tf);
		}
	}

	static Path createTempDataFile() throws IOException {
		var sn = new SecureRandom();
		var tf = Files.createTempFile("random", ".data");
		try(var out = Files.newOutputStream(tf)) {
			for(int i = 0 ; i < 10000; i++) {
				out.write(sn.nextInt(256));
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
}
