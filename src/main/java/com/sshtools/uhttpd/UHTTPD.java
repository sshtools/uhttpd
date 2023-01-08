/**
 * Copyright © 2023 JAdaptive Limited (support@jadaptive.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sshtools.uhttpd;

import static java.net.URLDecoder.decode;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class UHTTPD extends Thread implements Closeable {

	public static final String HDR_HOST = "host";
	public static final String HDR_UPGRADE = "upgrade";
	public static final String HDR_CONNECTION = "connection";
	public static final String HDR_CONTENT_TYPE = "content-type";
	public static final String HDR_CACHE_CONTROL = "cache-control";
	public static final String HDR_CONTENT_DISPOSITION = "content-disposition";
	public static final String HDR_CONTENT_LENGTH = "content-Length";
	
	private static final String WEBSOCKET_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	public interface Authenticator<C extends Credential> {
		Optional<Principal> authenticate(C credential) throws IllegalArgumentException;
	}

	public interface WebSocket extends Closeable {
		Client client();
		String protocol();
		int version();
		void send(String data);
		void send(ByteBuffer data);
	}

	public interface OnWebSocketData {
		void receive(ByteBuffer data, WebSocket websocket);
	}

	public interface OnWebSocketOpen {
		void open(WebSocket websocket);
	}
	
	public interface OnWebSocketHandshake {
		String handshake(Transaction tx, String... protocols);
	}

	public interface OnWebSocketClose {
		void closed(WebSocket websocket);
	}

	public interface OnWebSocketError {

		void error(WebSocket websocket, Throwable exception);
	}

	public static final class WebSocketBuilder {
		private Optional<OnWebSocketData> onData = Optional.empty();
		private Optional<OnWebSocketClose> onClose = Optional.empty();
		private Optional<OnWebSocketOpen> onOpen = Optional.empty();
		private Optional<OnWebSocketError> onError = Optional.empty();
		private Optional<OnWebSocketHandshake> onHandshake = Optional.empty();

		public WebSocketBuilder onData(OnWebSocketData onData) {
			this.onData = Optional.of(onData);
			return this;
		}

		public WebSocketBuilder onClose(OnWebSocketClose onClose) {
			this.onClose = Optional.of(onClose);
			return this;
		}

		public WebSocketBuilder onOpen(OnWebSocketOpen onOpen) {
			this.onOpen = Optional.of(onOpen);
			return this;
		}

		public WebSocketBuilder onError(OnWebSocketError onError) {
			this.onError = Optional.of(onError);
			return this;
		}
		
		public WebSocketBuilder onHandshake(OnWebSocketHandshake onHandshake) {
			this.onHandshake = Optional.of(onHandshake);
			return this;
		}
		
		public WebSocketHandler build() {
			return new WebSocketHandler(this);
		}

	}

	public static final class WebSocketHandler implements Handler {
		
		private final class WebSocketFrame {
			
			boolean fin, rsv1, rsv2, rsv3, mask;
			byte opCode;
			long payloadLength; 
			int key;
			byte[] applicationData;
			
			void read(InputStream in) throws IOException {
				var din = new DataInputStream(in);
				var b1 = din.read();
				if(b1 == -1)
					throw new EOFException();
				
				fin = (b1 & 0x01) != 0;
				rsv1 = (b1 & 0x02) != 0;
				rsv2 = (b1 & 0x03) != 0;
				rsv3 = (b1 & 0x04) != 0;
				
				if(rsv1 || rsv2 || rsv3) {
					throw new IOException("Extensions are not supported.");
				}
				opCode = (byte)(b1 >> 4 & 0xf);		
				
				b1 = din.read();
				if(b1 == -1)
					throw new EOFException();		
				mask = (b1 & 0x01) != 0;
				payloadLength = (long)(b1 >> 1 & 0x7f);
				if(payloadLength > 126) {
					payloadLength = din.readLong();
				}
				else if(payloadLength > 125) {
					payloadLength = din.readShort();
				}
				
				if(mask) {
					key = din.readInt();
				}
				
				// TODO 
				// extensionData = ....
				
				applicationData = new byte[(int)payloadLength]; // TODO will payload ever really be 64 bits?
				din.readFully(applicationData);
			}
		}

		private final class WebSocketProtocol implements WireProtocol {
			
			private WebSocketImpl ws;

			WebSocketProtocol(WebSocketImpl ws) {
				this.ws = ws;
			}

			@Override
			public void transact() throws IOException {
				onOpen.ifPresent(h -> h.open(ws));
				try {
					var frame = new WebSocketFrame();
					while(true) {
						frame.read(ws.client.in);
					}
				}
				finally {
					onClose.ifPresent(h -> h.closed(ws));
				}
			}
		}
		
		private final class WebSocketImpl implements WebSocket {
			private final Client client;
			private final String selectedProtocol;
			private final int version;

			private WebSocketImpl(Client client, String selectedProtocol, int version) {
				this.client = client;
				this.selectedProtocol = selectedProtocol;
				this.version = version;
			}

			@Override
			public void close() throws IOException {
				client.close();
			}

			@Override
			public Client client() {
				return client;
			}

			@Override
			public String protocol() {
				return selectedProtocol;
			}

			@Override
			public int version() {
				return version;
			}

			@Override
			public void send(ByteBuffer data) {
//						client.send(data);						
			}

			@Override
			public void send(String data) {
				// TODO Auto-generated method stub
			}
		}

		private final Optional<OnWebSocketData> onData;
		private final Optional<OnWebSocketError> onError;
		private final Optional<OnWebSocketClose> onClose;
		private final Optional<OnWebSocketOpen> onOpen;
		private final Optional<OnWebSocketHandshake> onHandshake;

		public WebSocketHandler(WebSocketBuilder builder) {
			this.onData = builder.onData;
			this.onError = builder.onError;
			this.onClose = builder.onClose;
			this.onOpen = builder.onOpen;
			this.onHandshake = builder.onHandshake;
		}

		@Override
		public void get(Transaction req) throws Exception {
			if (req.headerValueOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").containsIgnoreCase("upgrade")
			 && req.headerOr(HDR_UPGRADE).orElse("").equalsIgnoreCase("websocket")) {
				// TODO https://en.wikipedia.org/wiki/WebSocket
				var key = req.header("sec-websocket-Key");
				var proto = req.headerValue("sec-websocket-protocol").expand(",");
				var version = req.headerValue("sec-websocket-version").asInt();
				var hasher = MessageDigest.getInstance("SHA-1");
				var responseKeyData = WEBSOCKET_UUID + key;
				var responseKey = Base64.getEncoder().encodeToString(hasher.digest(responseKeyData.getBytes("UTF-8")));
				var selectedProtocol = onHandshake.isPresent() ? onHandshake.get().handshake(req, proto.values().toArray(new String[0])) : proto.values.isEmpty() ? "" : proto.values().get(0);
				var client = req.client();
				
				var ws = new WebSocketImpl(client, selectedProtocol, version);

				req.responseCode(Status.CONTINUE);
				req.responseText("Switching Protocols");
				req.header(HDR_CONNECTION, "upgrade");
				req.header(HDR_UPGRADE, "websocket");
				req.header("sec-websocket-protocol", selectedProtocol);
				req.header("sec-websocket-accept", responseKey);
				
				client.wireProtocol = new WebSocketProtocol(ws);
			}
		}

	}

	public final static class ServerBuilder {
		private int backlog = 10;
		private boolean daemon;
		private Map<Selector, Handler> handlers = new LinkedHashMap<>();
		private Optional<InetAddress> httpAddress = Optional.empty();
		private Optional<Integer> httpPort = Optional.of(8080);
		private Optional<InetAddress> httpsAddress = Optional.empty();
		private Optional<Integer> httpsPort = Optional.empty();
		private Optional<char[]> keyPassword = Optional.empty();
		private String keyStoreAlias = "uhttpd";
		private Optional<Path> keyStoreFile = Optional.empty();
		private Optional<char[]> keyStorePassword = Optional.empty();
		private String threadName = "UHTTPD";
		private boolean cache = true;
		private boolean keepAlive = true;
		private int keepAliveTimeoutSecs = 15;
		private int keepAliveMax = 100;
		private Optional<Integer> threads = Optional.empty();

		public ServerBuilder withoutCache() {
			this.cache = false;
			return this;
		}

		public ServerBuilder withoutKeepalive() {
			this.keepAlive = false;
			return this;
		}

		public ServerBuilder withKeepaliveTimeoutSecs(int keepAliveTimeoutSecs) {
			this.keepAliveTimeoutSecs = keepAliveTimeoutSecs;
			return this;
		}

		public ServerBuilder withKeepaliveMax(int keepAliveMax) {
			this.keepAliveMax = keepAliveMax;
			return this;
		}

		public ServerBuilder asDaemon() {
			daemon = true;
			return this;
		}

		public UHTTPD build() throws UnknownHostException, IOException {
			return new UHTTPD(this);
		}

		public ServerBuilder chain(Handler... handlers) {
			handle(ALL_SELECTOR, (req) -> {
				for (var h : handlers) {
					h.get(req);
					if (req.responsed())
						break;
				}
			});
			return this;
		}

		public ServerBuilder webSocket(String regexp, WebSocketHandler handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.GET), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder delete(String regexp, Handler... handler) {
			return handle(
					new CompoundSelector(new MethodSelector(Method.DELETE), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder get(String regexp, Handler... handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.GET), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder handle(Selector selector, Handler... handler) {
			if (handler.length == 0)
				throw new IllegalArgumentException("Expect at least one handler.");
			if (handler.length == 1)
				handlers.put(selector, handler[0]);
			else {
				handlers.put(selector, (req) -> {
					for (var h : handler) {
						h.get(req);
						if (req.responsed())
							break;
					}
				});
			}
			return this;
		}

		public ServerBuilder withFileResources(String regexpWithGroups, Path root) {
			handle(new RegularExpressionSelector(regexpWithGroups), new FileResources(regexpWithGroups, root));
			return this;
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups) {
			return withClasspathResources(regexpWithGroups, "");
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups, String prefix) {
			return withClasspathResources(regexpWithGroups,
					Optional.ofNullable(Thread.currentThread().getContextClassLoader()), prefix);
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader, String prefix) {
			handle(new RegularExpressionSelector(regexpWithGroups),
					new ClasspathResources(regexpWithGroups, loader, prefix));
			return this;
		}

		public ServerBuilder handle(String regexp, Handler... handler) {
			return handle(new RegularExpressionSelector(regexp), handler);
		}

		public ServerBuilder post(String regexp, Handler... handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.POST), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder withBacklog(int backlog) {
			this.backlog = backlog;
			return this;
		}

		public ServerBuilder withHttp(int httpPort) {
			this.httpPort = Optional.of(httpPort);
			return this;
		}

		public ServerBuilder withHttpAddress(InetAddress httpAddress) {
			this.httpAddress = Optional.of(httpAddress);
			return this;
		}

		public ServerBuilder withHttpAddress(String httpAddress) {
			try {
				this.httpAddress = Optional.of(InetAddress.getByName(httpAddress));
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid address.", e);
			}
			return this;
		}

		public ServerBuilder withHttps(int httpsPort) {
			this.httpsPort = Optional.of(httpsPort);
			return this;
		}

		public ServerBuilder withHttpsAddress(InetAddress httpsAddress) {
			this.httpsAddress = Optional.of(httpsAddress);
			return this;
		}

		public ServerBuilder withHttpsAddress(String httpsAddress) {
			try {
				this.httpsAddress = Optional.of(InetAddress.getByName(httpsAddress));
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid address.", e);
			}
			return this;
		}

		public ServerBuilder withKeyPassword(char[] keyPassword) {
			this.keyPassword = Optional.of(keyPassword);
			return this;
		}

		public ServerBuilder withKeyStoreAlias(String keyStoreAlias) {
			this.keyStoreAlias = keyStoreAlias;
			return this;
		}

		public ServerBuilder withKeyStoreFile(Path keyStoreFile) {
			this.keyStoreFile = Optional.of(keyStoreFile);
			return this;
		}

		public ServerBuilder withKeyStorePassword(char[] keyStorePassword) {
			this.keyStorePassword = Optional.of(keyStorePassword);
			return this;
		}

		public ServerBuilder withoutHttp() {
			this.httpPort = Optional.empty();
			return this;
		}

		public ServerBuilder withoutHttps() {
			this.httpsPort = Optional.empty();
			return this;
		}

		public ServerBuilder withThreadName(String threadName) {
			this.threadName = threadName;
			return this;
		}

		public ServerBuilder withThreads(int threads) {
			this.threads = Optional.of(threads);
			return this;
		}
	}

	public interface Part {
		String name();
	}

	public interface TextPart extends Part {
		

		Optional<String> value();

		default InputStream asStream() {
			return new ByteArrayInputStream(asString().getBytes());
		}

		default Reader asReader() {
			return new StringReader(asString());
		}

		default String asString() {
			return value().orElseThrow();
		}

		default long asLong() {
			return value().map(v -> Long.parseLong(v)).orElseThrow();
		}

		default boolean asBoolean() {
			return value().map(v -> Boolean.valueOf(v)).orElseThrow();
		}

		default int asInt() {
			return value().map(v -> Integer.parseInt(v)).orElseThrow();
		}

		default short asShort() {
			return value().map(v -> Short.parseShort(v)).orElseThrow();
		}

		default float asFloat() {
			return value().map(v -> Float.parseFloat(v)).orElseThrow();
		}

		default double asDouble() {
			return value().map(v -> Double.parseDouble(v)).orElseThrow();
		}

		default char asChar() {
			return value().map(v -> v.charAt(0)).orElseThrow();
		}

		default byte asByte() {
			return value().map(v -> Byte.parseByte(v)).orElseThrow();
		}

		default BigDecimal asBigDecimal() {
			return value().map(v -> new BigDecimal(v)).orElseThrow();
		}
	}
	
	public interface WireProtocol {

		void transact() throws IOException;
	}


	public interface Content {
		Optional<Long> size();

		Optional<String> contentType();

		InputStream asStream();

		Iterable<Part> asParts();

		default Optional<FormData> formData(String name) {
			return part(name, FormData.class);
		}

		default FormData asFormData(String name) {
			return formData(name).orElseThrow();
		}

		<P extends Part> Optional<P> part(String name, Class<P> clazz);
	}

	public interface Credential {
		Optional<Principal> result(boolean success); 
	}

	public interface Handler {
		void get(Transaction req) throws Exception;
	}

	private final static class FileResources implements Handler {

		private final Path root;
		private final Pattern regexpWithGroups;

		private FileResources(String regexpWithGroups, Path root) {
			this.root = root;
			this.regexpWithGroups = Pattern.compile(regexpWithGroups);
		}

		@Override
		public void get(Transaction req) throws Exception {
			var matcher = regexpWithGroups.matcher(req.path().toString());
			if (matcher.find()) {
				var path = matcher.group(1);
				while (path.startsWith("/"))
					path = path.substring(1);
				var fullPath = root.resolve(Paths.get(path).normalize());
				LOG.log(Level.DEBUG, "Location resource for {0}", path);
				if (Files.exists(fullPath)) {
					if (!Files.isDirectory(fullPath)) {
						LOG.log(Level.DEBUG, "Location resource for {0}", fullPath);
						req.responseLength(Files.size(fullPath));
						req.responseType(getMimeType(fullPath.toUri().toURL()));
						req.response(Files.newInputStream(fullPath));
					}
				} else
					throw new FileNotFoundException(fullPath.toString());
			} else
				throw new IllegalStateException(
						String.format("Handling a request where the pattern '%s' does not match the path '%s'",
								regexpWithGroups, req.path()));
		}

	}

	private final static class ClasspathResources implements Handler {

		private final String prefix;
		private Optional<ClassLoader> loader;
		private final Pattern regexpWithGroups;

		public ClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader, String prefix) {
			this.loader = loader;
			this.prefix = prefix;
			this.regexpWithGroups = Pattern.compile(regexpWithGroups);
		}

		@Override
		public void get(Transaction req) throws Exception {
			var matcher = regexpWithGroups.matcher(req.path().toString());
			if (matcher.find()) {
				var path = matcher.group(1);
				LOG.log(Level.DEBUG, "Locating resource for {0}", path);
				var fullPath = prefix + Paths.get(path).normalize().toString();
				var url = loader.orElse(ClasspathResources.class.getClassLoader()).getResource(fullPath);
				if (url == null)
					throw new FileNotFoundException(fullPath);
				else {
					LOG.log(Level.DEBUG, "Resource @{0}", url);
					var conx = url.openConnection();
					req.responseLength(conx.getContentLengthLong());
					req.responseType(conx.getContentType());
					req.response(url.openStream());
				}
			} else
				throw new IllegalStateException(
						String.format("Handling a request where the pattern '%s' does not match the path '%s'",
								regexpWithGroups, req.path()));
		}

	}

	public final static class HttpBasicAuthentication {

		private Authenticator<UsernameAndPassword> authenticator;
		private Optional<String> realm = Optional.empty();

		HttpBasicAuthentication(Authenticator<UsernameAndPassword> authenticator) {
			this.authenticator = authenticator;
		}

		public Handler build() throws UnknownHostException, IOException {
			return new Handler() {
				@Override
				public void get(Transaction req) throws Exception {
					var auth = req.headerOr("Authorization");
					if (auth.isPresent()) {
						var tkns = new StringTokenizer(auth.get());
						var type = tkns.nextToken();
						if (type.equalsIgnoreCase("Basic")) {
							var decoded = new String(Base64.getDecoder().decode(tkns.nextToken())).split(":");
							var principal = authenticator.authenticate(new UsernameAndPassword() {
								@Override
								public char[] password() {
									return (decoded.length < 2 ? "" : decoded[1]).toCharArray();
								}

								@Override
								public String username() {
									return decoded[0];
								}
							});
							if (principal.isPresent()) {
								req.authenticate(principal.get());
								return;
							}
						}
					}

					/* Need auth */
					req.unauthorized(realm.orElse("UHTTPD"));
				}
			};
		}

		public HttpBasicAuthentication withRealm(String realm) {
			this.realm = Optional.of(realm);
			return this;
		}
	}

	public enum Method {
		GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
	}

	public static class FormData implements TextPart {

		private final Optional<String> contentType;
		private final Optional<String> filename;
		private final String name;
		private final Optional<String> value;

		FormData(String contentType, String contentDisposition, String value) {
			var map = Named.parseSeparatedStrings(contentDisposition);
			this.name = map.get("name").asString();
			this.value = Optional.ofNullable(value);
			this.contentType = Optional.ofNullable(contentType);
			this.filename = Optional.ofNullable(map.get("filename")).map(n -> n.asString());
		}

		public final Optional<String> contentType() {
			return contentType;
		}

		public final Optional<String> filename() {
			return filename;
		}

		@Override
		public String name() {
			return name;
		}

		@Override
		public Optional<String> value() {
			return value;
		}
	}

	public static class Named implements TextPart {
		public static final Named EMPTY = new Named("", Collections.emptyList());

		static Named parseHeader(String raw) {
			var idx = raw.indexOf(':');
			if (idx == -1)
				throw new IllegalArgumentException("Malformed header.");
			return new Named(raw.substring(0, idx).toLowerCase(), raw.substring(idx + 1).trim());
		}

		static Named parseParameter(String raw) {
			var idx = raw.indexOf('=');
			String name = null;
			String value = null;

			try {
				if (idx == -1) {
					name = decode(raw, "UTF-8");
				} else {
					name = decode(raw.substring(0, idx), "UTF-8");
					value = decode(raw.substring(idx + 1), "UTF-8");
				}
			} catch (UnsupportedEncodingException uee) {
				throw new IllegalStateException(uee);
			}

			return new Named(name, value);
		}

		static Map<String, Named> parseSeparatedStrings(String raw) {
			return parseSeparatedStrings(raw, ";");
		}

		static Map<String, Named> parseSeparatedStrings(String raw, String separator) {
			var map = new LinkedHashMap<String, List<String>>();

			for (var parm : raw.split(separator)) {

				var idx = parm.indexOf('=');
				String name = null;
				String value = null;

				if (idx == -1) {
					name = parm.trim();
				} else {
					name = parm.substring(0, idx).trim();
					value = parm.substring(idx + 1).trim();
					if (value.startsWith("\""))
						value = value.substring(1);
					if (value.endsWith("\""))
						value = value.substring(0, value.length() - 1);
				}

				var l = map.get(name);
				if (l == null) {
					l = new ArrayList<>();
					map.put(name, l);
				}
				if (value != null) {
					l.add(value);
				}
			}

			return map.entrySet().stream().map(e -> new Named(e.getKey(), e.getValue()))
					.collect(Collectors.toMap(nvp -> nvp.name(), nvp -> nvp));
		}

		static Map<String, Named> parseParameters(String raw) {
			var map = new LinkedHashMap<String, List<String>>();

			for (var parm : raw.split("&")) {

				var idx = parm.indexOf('=');
				String name = null;
				String value = null;

				try {
					if (idx == -1) {
						name = decode(parm, "UTF-8");
					} else {
						name = decode(parm.substring(0, idx), "UTF-8");
						value = decode(parm.substring(idx + 1), "UTF-8");
					}
				} catch (UnsupportedEncodingException uee) {
					throw new IllegalStateException(uee);
				}

				var l = map.get(name);
				if (l == null) {
					l = new ArrayList<>();
					map.put(name, l);
				}
				if (value != null) {
					l.add(value);
				}
			}

			return map.entrySet().stream().map(e -> new Named(e.getKey(), e.getValue()))
					.collect(Collectors.toMap(nvp -> nvp.name(), nvp -> nvp));
		}

		private final String name;

		private final List<String> values;

		Named(String name, List<String> values) {
			super();
			this.name = name;
			this.values = values;
		}

		public boolean containsIgnoreCase(String value) {
			for(var n : values) {
				if(n.equalsIgnoreCase(value))
					return true;
			}
			return false;
		}

		Named(String name, String value) {
			this(name, value == null ? Collections.emptyList() : Arrays.asList(value));
		}

		public String name() {
			return name;
		}

		@Override
		public String toString() {
			return "Named [name=" + name + ", values=" + values + "]";
		}

		@Override
		public Optional<String> value() {
			return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
		}
		
		public Named expand(String separator) {
			return new Named(name, Arrays.asList(asString().split(separator)).
					stream().map(s -> s.trim()).collect(Collectors.toList()));
		}

		public List<String> values() {
			return Collections.unmodifiableList(values);
		}
	}

	public enum Protocol {
		HTTP_0, HTTP_1_0, HTTP_1_1, HTTP_2, HTTP_3;

		String text() {
			return "HTTP/" + (name().substring(5).replace('_', '.'));
		}
	}

	public final static class Transaction {

		private Optional<Status> code = Optional.empty();

		private final Map<String, Named> incomingHeaders = new LinkedHashMap<>();
		private final Method method;
		private Optional<Long> responseLength = Optional.empty();
		private Optional<String> outgoingContentType = Optional.empty();
		private final Map<String, Named> outgoingHeaders = new LinkedHashMap<>();
		private final Map<String, Named> parameters = new LinkedHashMap<>();
		private final Path path;
		private Optional<Principal> principal = Optional.empty();
		private final Protocol protocol;
		private Optional<Object> response = Optional.empty();
		private Optional<String> responseText = Optional.empty();
		private final String urlHost;
		private Supplier<Optional<Content>> contentSupplier;
		private Optional<Selector> selector = Optional.empty();
		private final List<String> matches = new ArrayList<>();
		private final Client client;

		Transaction(String pathSpec, Method method, Protocol protocol, Client client) {
			this.method = method;
			this.protocol = protocol;
			this.client = client;

			var sepIdx = pathSpec.indexOf("://");
			if (sepIdx == -1) {
				if (!pathSpec.startsWith("/")) {
					pathSpec = "/" + pathSpec;
				}
				urlHost = null;
			} else {
				var idx = pathSpec.indexOf('/', sepIdx + 3);
				urlHost = idx == -1 ? pathSpec.substring(sepIdx + 2) : pathSpec.substring(sepIdx + 2);
				pathSpec = idx == -1 ? "/" : pathSpec.substring(idx);
			}

			var idx = pathSpec.indexOf('?');
			if (idx == -1) {
				path = Paths.get(pathSpec);
			} else {
				path = Paths.get(pathSpec.substring(0, idx));
				parameters.putAll(Named.parseParameters(pathSpec.substring(idx + 1)));
			}
		}
		
		public Client client() {
			return client;
		}

		public List<String> matches() {
			return Collections.unmodifiableList(matches);
		}

		public Selector selector() {
			return selector.orElseThrow();
		}

		public Content request() {
			return contentSupplier.get().orElseThrow();
		}

		public Optional<Selector> selectorOr() {
			return selector;
		}

		public Optional<Content> requestOr() {
			return contentSupplier.get();
		}

		public void authenticate(Principal principal) {
			this.principal = Optional.of(principal);
		}

		public boolean authenticated() {
			return principal.isPresent();
		}

		public Transaction responseLength(long responseLength) {
			this.responseLength = responseLength == -1 ? Optional.empty() : Optional.of(responseLength);
			return this;
		}

		public Transaction responseType(String contentType) {
			outgoingContentType = Optional.ofNullable(contentType);
			return this;
		}

		public Transaction found(String location) {
			responseCode(Status.FOUND);
			header("Location", location == null ? "/" : location);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public String header(String name) {
			return headerOr(name).orElseThrow();
		}

		public Optional<String> headerOr(String name) {
			return headerValueOr(name).map(h -> h.value().get());
		}

		public Named headerValue(String name) {
			return headerValueOr(name).orElseThrow();
		}

		public Optional<Named> headerValueOr(String name) {
			return incomingHeaders.values().stream().filter(h -> h.name().equals(name.toLowerCase())).map(h -> Optional.of(h))
					.reduce((f, s) -> f).orElse(Optional.empty());
		}

		public Transaction header(String name, String value) {
			outgoingHeaders.put(name.toLowerCase(), new Named(name.toLowerCase(), value));
			return this;
		}

		public final List<Named> headers() {
			return Collections.unmodifiableList(new ArrayList<>(incomingHeaders.values()));
		}

		public String hostname() {
			var hdr = headerOr(HDR_HOST);
			return hdr.isPresent() ? hdr.get() : urlHost;
		}

		public Method method() {
			return method;
		}

		public Transaction notFound() {
			responseCode(Status.NOT_FOUND);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public Transaction notImplemented() {
			responseCode(Status.NOT_IMPLEMENTED);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public Optional<Named> parameterOr(String name) {
			return Optional.ofNullable(parameters.get(name));
		}

		public Named parameter(String name) {
			return parameterOr(name).orElseThrow();
		}

		public Iterable<String> parameterNames() {
			return parameters.keySet();
		}

		public Iterable<Named> parameters() {
			return parameters.values();
		}

		public final Path path() {
			return path;
		}

		public Optional<Principal> principal() {
			return principal;
		}

		public Protocol protocol() {
			return protocol;
		}

		public Transaction response(String responseType, Object response) {
			responseText(responseType);
			this.response = Optional.of(response);
			return this;
		}

		public Transaction response(Object response) {
			this.response = Optional.of(response);
			return this;
		}

		public Transaction responseCode(Status code) {
			this.code = Optional.of(code);
			return this;
		}

		public boolean responsed() {
			return code.isPresent();
		}

		public Transaction responseText(String text) {
			this.responseText = Optional.of(text);
			return this;
		}

		@Override
		public String toString() {
			return "Request [path=" + path + ", parameters=" + parameters + ", incomingHeaders=" + incomingHeaders
					+ ", outgoingHeaders=" + outgoingHeaders + ", outgoingContentLength=" + responseLength
					+ ", outgoingContentType=" + outgoingContentType + ", response=" + response + ", code=" + code
					+ ", responseText=" + responseText + ", principal=" + principal + ", method=" + method
					+ ", protocol=" + protocol + ", urlHost=" + urlHost + "]";
		}

		public Transaction unauthorized(String realm) {
			responseCode(Status.UNAUTHORIZED);
			responseType("text/plain");
			header("WWW-Authenticate", String.format("Basic realm=\"%s\"", realm));
			responseLength = Optional.empty();
			return this;

		}

		public void error(Exception ise) {
			responseCode(Status.INTERNAL_SERVER_ERROR);
			if (ise.getMessage() != null)
				responseText(ise.getMessage());
			responseType("text/plain");
			responseLength = Optional.empty();

		}

		public boolean hasResponseHeader(String name) {
			return outgoingHeaders.containsKey(name);
		}
	}

	public interface Selector {
		boolean matches(Transaction request);
	}

	public enum Status {

		CONTINUE(100, "Continue"), BAD_REQUEST(400, "Bad Request"), FORBIDDEN(403, "Forbidden"), FOUND(302, "Found"),
		INTERNAL_SERVER_ERROR(500, "Not Found"), MOVED_PERMANENTLY(301, "Moved Permanently"),
		NOT_FOUND(404, "Not Found"), NOT_IMPLEMENTED(501, "Not Implemented"), OK(200, "OK"),
		SERVICE_UNAVAILABLE(503, "Service Unavailable"), UNAUTHORIZED(401, "Unauthorized");

		private int code;
		private String text;

		Status(int code, String text) {
			this.code = code;
			this.text = text;
		}

		public int getCode() {
			return code;
		}

		public String getText() {
			return text;
		}

	}

	public interface UsernameAndPassword extends Credential {
		char[] password();

		String username();
		
		default Optional<Principal> result(boolean success) {
			if(success) {
				return Optional.of(new Principal() {
					@Override
					public String getName() {
						return username();
					}
				});
			}
			else
				return Optional.empty();
		}
	}

	private final static class URLEncodedFormDataPartIterator implements Iterator<Part> {

		Part next;
		Reader reader;
		StringBuilder buffer = new StringBuilder(256);
		long size;
		long read;

		URLEncodedFormDataPartIterator(Reader reader, long size) {
			this.reader = reader;
			this.size = size;
		}

		void checkNext() {
			if (next == null) {
				char ch;
				buffer.setLength(0);
				;
				try {
					while (read < size && (ch = (char) reader.read()) != -1) {
						read++;
						if (ch == '&') {
							// Next parameter
							break;
						} else
							buffer.append(ch);
					}
					next = Named.parseParameter(buffer.toString());
				} catch (IOException ioe) {
					throw new IllegalStateException("I/O error while reading URL encoded form parameters.");
				}
			}
		}

		@Override
		public boolean hasNext() {
			checkNext();
			return next != null;
		}

		@Override
		public Part next() {
			try {
				checkNext();
				return next;
			} finally {
				next = null;
			}
		}

	}

	private final static class MultipartFormDataPartIterator implements Iterator<Part> {

		FormData next;
		StringBuilder buffer = new StringBuilder(256);
		String contentDisposition;
		String contentType;
		StringBuilder content;
		long read;
		boolean end;

		final Reader reader;
		String boundary;
		final long size;

		MultipartFormDataPartIterator(Reader reader, String boundary, long size) {
			this.reader = reader;
			this.size = size;
			this.boundary = boundary;
		}

		void checkNext() {
			if (next == null) {
				char ch;
				buffer.setLength(0);
				try {
					while (!end && read < size && (ch = (char) reader.read()) != -1) {

						read++;
						if (ch == '\n') {
							continue;
						}
						if (boundary == null) {
							if (ch == '\r') {
								boundary = buffer.toString();
								buffer.setLength(0);
							} else
								buffer.append(ch);
						} else if (ch == '\r') {
							var line = buffer.toString();
							if (line.startsWith(boundary)) {
								// Next part
								end = line.endsWith("--");
								break;
							} else if (line.toLowerCase().startsWith(HDR_CONTENT_TYPE + ": ")) {
								contentType = Named.parseHeader(line).asString();
							} else if (line.toLowerCase().startsWith(HDR_CONTENT_DISPOSITION + ": ")) {
								contentDisposition = Named.parseHeader(line).asString();
							} else if (line.equals("")) {
								// content will start
								content = new StringBuilder();
							} else {
								content.append(line);
							}
							buffer.setLength(0);
						} else {
							buffer.append(ch);
						}
					}
					try {
						next = new FormData(contentType, contentDisposition, content.toString());
					} finally {
						content = null;
					}
				} catch (IOException ioe) {
					throw new IllegalStateException("I/O error while reading URL encoded form parameters.");
				}
			}
		}

		@Override
		public boolean hasNext() {
			checkNext();
			return next != null;
		}

		@Override
		public Part next() {
			try {
				checkNext();
				return next;
			} finally {
				next = null;
				contentDisposition = null;
				contentType = null;
			}
		}

	}

	private final static class AllSelector implements Selector {
		@Override
		public boolean matches(Transaction request) {
			return true;
		}
	}

	private static class CompoundSelector implements Selector {
		private Selector[] selectors;

		CompoundSelector(Selector... selectors) {
			this.selectors = selectors;
		}

		@Override
		public boolean matches(Transaction request) {
			for (var s : selectors) {
				if (!s.matches(request)) {
					return false;
				}
			}
			return true;
		}
	}

	private static class MethodSelector implements Selector {

		private List<Method> methods;

		MethodSelector(Method... methods) {
			this.methods = Arrays.asList(methods);
		}

		@Override
		public boolean matches(Transaction request) {
			return methods.contains(request.method());
		}

	}

	private static class RegularExpressionSelector implements Selector {

		private Pattern pattern;

		RegularExpressionSelector(String regexp) {
			pattern = Pattern.compile(regexp);
		}

		@Override
		public boolean matches(Transaction req) {
			var path = req.path().toString();
			return pattern.matcher(path).matches();
		}

	}

	final static Logger LOG = System.getLogger("UHTTPD");

	private final static Selector ALL_SELECTOR = new AllSelector();

	public static HttpBasicAuthentication httpBasicAuthentication(Authenticator<UsernameAndPassword> authenticator) {
		return new HttpBasicAuthentication(authenticator);
	}

	public static ServerBuilder server() {
		return new ServerBuilder();
	}

	public static WebSocketBuilder websocket() {
		return new WebSocketBuilder();
	}
	
	public static final class Client implements Runnable, Closeable {
		
		final Socket socket;
		final int keepAliveTimeoutSecs;
		final int keepAliveMax;
		final Map<Selector, Handler> contentFactories;
		final Closeable server;
		final boolean keepAlive;
		final boolean cache;
		final InputStream in;
		final OutputStream out;
		final BufferedReader reader;
		final PrintWriter writer;
		
		boolean closed = false;
		int times = 0;
		WireProtocol wireProtocol;
		
		Client(Socket socket, boolean cache, boolean keepAlive, int keepAliveTimeoutSecs, int keepAliveMax, Map<Selector, Handler> contentFactories, Closeable server) throws IOException {
			this.socket = socket;
			this.cache = cache;
			this.keepAlive = keepAlive;
			this.keepAliveTimeoutSecs = keepAliveTimeoutSecs;
			this.keepAliveMax = keepAliveMax;
			this.contentFactories = contentFactories;
			this.server = server;
			
			in = socket.getInputStream();
			out = socket.getOutputStream();
			reader = new BufferedReader(new InputStreamReader(in));
			writer = new PrintWriter(new OutputStreamWriter(out));
			
			wireProtocol = new HTTP11WireProtocol(this);
		}
		
		public WireProtocol wireProtocol() {
			return wireProtocol;
		}

		@Override
		public void close() throws IOException {
			if(!closed) {
				closed = true;
				try {
					socket.close();
				} catch (IOException ioe) {
				}
			}
		}

		@Override
		public void run() {
			try {
				var client = socket.getInetAddress();
				if (client == null) {
					LOG.log(Level.ERROR, """
							Socket was lost between accepting it and starting to handle it. This can be caused
							by the system socket factory being swapped out for another while the boot HTTP server
							is running. Closing down the server now, it has become useless!
							""");
					try {
						server.close();
					} catch (IOException e) {
					}
				} else {
					try {
						LOG.log(Level.DEBUG, "{0} connected to server", client.getHostName());
						do {
							wireProtocol.transact();
							times++;
							socket.getOutputStream().flush();
						} while (times < keepAliveMax);
					} catch(EOFException e) {
						e.printStackTrace();
						LOG.log(Level.TRACE, "EOF.", e);
					} catch (Exception e) {
						LOG.log(Level.ERROR, "Failed handling connection.", e);
					}
				}
			} catch (Exception e) {
				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Failed processing connection.", e);
			} finally {
				try {
					close();
				} catch (IOException e) {
				}
			}
			
		}
		
	}
	
	static final class HTTP11WireProtocol implements WireProtocol {
		
		final Client client;
		
		HTTP11WireProtocol(Client client) {
			this.client = client;
		}

		@Override
		public void transact() throws IOException {
			var reader = client.reader;
			var line = reader.readLine();
			if (line == null)
				throw new EOFException();
			var tkns = new StringTokenizer(line);
			var firstToken = tkns.nextToken();
			var method = Method.GET;
			var proto = Protocol.HTTP_0;
			String uri;
			if (tkns.hasMoreTokens()) {
				method = Method.valueOf(firstToken);
				uri = tkns.nextToken();
				proto = Protocol.valueOf(tkns.nextToken().replace('/', '_').replace('.', '_'));

				if (Protocol.HTTP_1_1.compareTo(proto) > 0) {
					throw new UnsupportedOperationException(
							String.format("Only currently supports up to %s", Protocol.HTTP_1_1));
				}
			} else {
				uri = firstToken;
			}
			var req = new Transaction(uri, method, proto, client);
			req.contentSupplier = new Supplier<>() {

				private Optional<Content> content;
				private boolean asStream;
				private boolean asParts;
				private boolean asNamedParts;
				private List<Part> parts;

				@Override
				public Optional<Content> get() {
					if (content == null) {
						content = Optional.ofNullable(new Content() {
							@Override
							public Optional<Long> size() {
								return req.headerValueOr(HDR_CONTENT_LENGTH).map(o -> o.asLong());
							}

							@Override
							public Optional<String> contentType() {
								return req.headerOr(HDR_CONTENT_TYPE);
							}

							@Override
							public InputStream asStream() {
								if (asParts || asNamedParts)
									throw new IllegalStateException("Already have content as named or iterated parts.");
								asStream = true;
								return client.in;
							}

							@Override
							public Iterable<Part> asParts() {
								if (asStream || asNamedParts) {
									throw new IllegalStateException("Already have content as stream or named parts.");
								}
								asParts = true;
								return asPartsImpl();
							}

							@SuppressWarnings("unchecked")
							@Override
							public <P extends Part> Optional<P> part(String name, Class<P> clazz) {
								if (asStream || asParts) {
									throw new IllegalStateException("Already have content as stream or iterated parts.");
								}
								for (var part : asPartsImpl()) {
									if (part.name().equals(name))
										return (Optional<P>) Optional.of(part);
								}

								return Optional.empty();
							}

							Iterable<Part> asPartsImpl() {
								if (parts == null) {
									parts = new ArrayList<>();
									return new Iterable<Part>() {
										@Override
										public Iterator<Part> iterator() {
											var it = iteratorImpl(reader);
											return new Iterator<Part>() {

												@Override
												public boolean hasNext() {
													return it.hasNext();
												}

												@Override
												public Part next() {
													var next = it.next();
													parts.add(next);
													return next;
												}

											};
										}

										private Iterator<Part> iteratorImpl(BufferedReader input) {
											var content = Named.parseSeparatedStrings(contentType().get());
											var type = content.values().iterator().next();
											switch (type.name()) {
											case "multipart/form-data":
												return new MultipartFormDataPartIterator(input,
														content.containsKey("boundary") ? content.get("boundary").asString()
																: null,
														size().orElse(Long.MAX_VALUE));
											case "application/x-www-form-urlencoded":
												return new URLEncodedFormDataPartIterator(input,
														size().orElse(Long.MAX_VALUE));
											default:
												throw new UnsupportedOperationException("Unknown content encoding.");
											}
										}
									};
								}
								return parts;
							}
						});
					}
					return content;
				}

			};

			/* Read headers up to content */
			while ((line = reader.readLine()) != null && !line.equals("")) {
				if (LOG.isLoggable(Level.TRACE))
					LOG.log(Level.TRACE, line);
				var nvp = Named.parseHeader(line);
				req.incomingHeaders.put(nvp.name, nvp);
			}

			var close = !client.keepAlive || Protocol.HTTP_1_1.compareTo(proto) < 0
					||  req.headerValueOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").containsIgnoreCase("close");

			if (proto.compareTo(Protocol.HTTP_1_0) > 0) {
				req.headerOr(HDR_HOST).orElseThrow();
			}

			for (var c : client.contentFactories.entrySet()) {
				if (c.getKey().matches(req)) {
					req.selector = Optional.of(c.getKey());
					try {
						c.getValue().get(req);
					} catch (FileNotFoundException fnfe) {
						req.notFound();
					} catch (Exception ise) {
						LOG.log(Level.ERROR, "Request handling failed.", ise);
						req.error(ise);
					}

					if (req.responsed()) {
						respond(req, close);
						return;
					} else if (req.response.isPresent())
						break;
				}
			}

			if (!req.response.isPresent()) {
				req.notFound();
			}

			respond(req, close);
			
			client.socket.setSoTimeout(client.keepAliveTimeoutSecs * 1000);
		}
		
		private void respond(Transaction req, boolean closed) throws IOException {

			var status = req.code.orElse(Status.OK);
			var close = false;

			if (status.getCode() >= 300)
				close = true;

			print(req.protocol().text());
			print(" ");
			print(status.code);
			print(" ");
			print(req.responseText.orElse(status.getText()));
			newline();

			var responseLength = req.responseLength;
			byte[] responseData = null;

			/* Do our best to get some kind of content length so keep alive works */
			if (req.response.isPresent()) {
				var resp = req.response.get();
				if (resp instanceof ByteBuffer) {
					responseLength = Optional.of((long) ((ByteBuffer) resp).remaining());
				} else if (resp instanceof ByteBuffer) {
					var bb = (ByteBuffer) resp;
					responseData = new byte[bb.remaining()];
					bb.get(responseData);
					responseLength = Optional.of((long) responseData.length);
				} else if (resp instanceof byte[]) {
					responseData = (byte[]) resp;
					responseLength = Optional.of((long) responseData.length);
				} else if (!(resp instanceof InputStream) && !(resp instanceof Reader)) {
					responseData = String.valueOf(resp).getBytes();
					responseLength = Optional.of((long) responseData.length);
				}
			}

			if (responseLength.isPresent()) {
				print(HDR_CONTENT_LENGTH);
				print(": ");
				print(responseLength.get());
				newline();
			} /* else {
				close = true;
			} */
			
			if(!req.hasResponseHeader(HDR_CONNECTION)) {
				if (close && req.protocol.compareTo(Protocol.HTTP_2) < 0) {
					print(HDR_CONNECTION);
					println(": close");
				} else if (req.protocol.compareTo(Protocol.HTTP_1_0) > 0 && req.protocol.compareTo(Protocol.HTTP_2) < 0) {
					print(HDR_CONNECTION);
					println(": keep-alive");
				}
			}
			
			print(HDR_CONTENT_TYPE);
			print(": ");
			print(req.outgoingContentType.orElse("text/plain"));
			newline();
			for (var nvp : req.outgoingHeaders.values()) {
				print(nvp.name());
				print(": ");
				print(nvp.value().orElse(""));
				newline();
			}
			if (!client.cache) {
				print(HDR_CACHE_CONTROL);
				println( ": no-cache");
			}
			newline();
			flush();
			if (req.response.isPresent()) {
				var resp = req.response.get();
				if (resp instanceof InputStream) {
					try (var in = (InputStream) resp) {
						in.transferTo(client.out);
					}
				} else if (resp instanceof Reader) {
					try (var in = (Reader) resp) {
						in.transferTo(client.writer);
					}
				} else {
					client.out.write(responseData);
				}
			}
			flush();
			if(close)
				throw new EOFException();
		}

		private void flush() throws IOException {
			client.writer.flush();
		}

		private void newline() throws IOException {
			client.writer.append("\r\n");
		}
		
		private void print(Object text) throws IOException {
			client.writer.append(text.toString());
		}

		private void println(Object text) throws IOException {
			print(text);
			newline();
		}
	}

	private final int backlog;
	private final boolean cache;
	private final Map<Selector, Handler> contentFactories = new LinkedHashMap<>();
	private final Optional<InetAddress> httpAddress;
	private final Optional<Integer> httpPort;
	private final Optional<InetAddress> httpsAddress;
	private final Optional<Integer> httpsPort;
	private final Optional<char[]> keyPassword;
	private final String keyStoreAlias;
	private final Optional<Path> keyStoreFile;
	private final Optional<char[]> keyStorePassword;
	private final boolean keepAlive;
	private final int keepAliveTimeoutSecs;
	private final int keepAliveMax;

	private boolean open = true;
	private Thread otherThread;
	private ExecutorService pool;
	private ServerSocket serversocket;
	private SSLServerSocket sslServersocket;

	private UHTTPD(ServerBuilder builder) throws UnknownHostException, IOException {
		super(builder.threadName);
		setDaemon(builder.daemon);
		httpPort = builder.httpPort;
		httpsPort = builder.httpsPort;
		httpAddress = builder.httpAddress;
		httpsAddress = builder.httpsAddress;
		keyStoreFile = builder.keyStoreFile;
		keyStorePassword = builder.keyStorePassword;
		keyPassword = builder.keyPassword;
		keyStoreAlias = builder.keyStoreAlias;
		backlog = builder.backlog;
		contentFactories.putAll(builder.handlers);
		cache = builder.cache;
		keepAlive = builder.keepAlive;
		keepAliveTimeoutSecs = builder.keepAliveTimeoutSecs;
		keepAliveMax = builder.keepAliveMax;
		pool = builder.threads.isPresent() ? Executors.newFixedThreadPool(builder.threads.get())
				: Executors.newCachedThreadPool();

		if (httpPort.isPresent()) {
			LOG.log(Level.INFO, "Starting HTTP server on port {0}", httpPort.get());
			serversocket = new ServerSocket(httpPort.get(), backlog, httpAddress.orElse(InetAddress.getByName("127.0.0.1")));
			serversocket.setReuseAddress(true);
		}

		if (httpsPort.isPresent()) {
			LOG.log(Level.INFO, "Start HTTPS server on port {0}", httpsPort.get());

			SSLContext sc = null;
			try {
				KeyStore ks = null;
				KeyManagerFactory kmf = null;

				if (keyStoreFile.isPresent() && Files.exists(keyStoreFile.get())) {
					LOG.log(Level.INFO, "Using keystore {0}", keyStoreFile.get());
					try (var in = Files.newInputStream(keyStoreFile.get())) {
						ks = loadKeyStoreFromJKS(in, keyStorePassword.orElse(new char[0]));
						kmf = KeyManagerFactory.getInstance("SunX509");
						kmf.init(ks, keyPassword.orElse(keyStorePassword.orElse(new char[0])));
					} catch (Exception e) {
						LOG.log(Level.ERROR, "Failed to load temporary keystore, reverting to default.", e);
						ks = null;
					}
				}

				if (ks == null) {
					LOG.log(Level.INFO, "Using default keystore");

					ks = KeyStore.getInstance("JKS");
				}

				sc = SSLContext.getInstance("TLS");
				sc.init(kmf.getKeyManagers(), null, null);
			} catch (Exception e) {
				throw new IOException("Failed to configure SSL.", e);
			}

			var ssf = sc.getServerSocketFactory();
			sslServersocket = (SSLServerSocket) ssf.createServerSocket(httpsPort.get(), backlog,
					httpsAddress.orElse(InetAddress.getLocalHost()));
			sslServersocket.setReuseAddress(true);
		}
	}

	@Override
	public void close() throws IOException {
		if (!open)
			throw new IOException("Already closed.");
		LOG.log(Level.INFO, "Closing Mini HTTP server.");
		open = false;
		try {
			serversocket.close();
		} finally {
			try {
				sslServersocket.close();
			} finally {
				try {
					join();
				} catch (InterruptedException e) {
				} finally {
					if (otherThread != null) {
						try {
							otherThread.join();
						} catch (InterruptedException e) {
						}
					}
				}
				pool.shutdown();
			}
		}
	}

	public boolean isCaching() {
		return cache;
	}

	@Override
	public void run() {

		/* Run, keeping number of thread used to minimum required for configuration */

		if (serversocket == null) {
			/* HTTPS only */
			runOn(sslServersocket);
		} else if (sslServersocket == null) {
			/* HTTP only */
			runOn(serversocket);
		} else if (serversocket != null && sslServersocket != null) {
			/* Both */
			otherThread = new Thread(getName() + "SSL") {
				public void run() {
					runOn(serversocket);
				}
			};
			otherThread.setDaemon(true);
			otherThread.start();
			runOn(sslServersocket);
			try {
				otherThread.join();
			} catch (InterruptedException e) {
			}
		} else
			throw new IllegalStateException();
	}

	private static String getMimeType(URL url) {
		try {
			URLConnection conx = url.openConnection();
			try {
				String contentType = conx.getContentType();
				return contentType;
			} finally {
				try {
					conx.getInputStream().close();
				} catch (IOException ioe) {
				}
			}
		} catch (IOException ioe) {
			return URLConnection.guessContentTypeFromName(Paths.get(url.getPath()).getFileName().toString());
		}
	}

	private KeyStore loadKeyStoreFromJKS(InputStream jksFile, char[] passphrase)
			throws KeyStoreException, NoSuchAlgorithmException, IOException, NoSuchProviderException,
			UnrecoverableKeyException, CertificateException {

		var keystore = KeyStore.getInstance("JKS");
		keystore.load(jksFile, passphrase);
		return keystore;
	}

	private void runOn(ServerSocket so) {
		while (open) {
			LOG.log(Level.DEBUG, "Waiting for connection");
			try {
				pool.execute(new Client(so.accept(), cache, keepAlive, keepAliveTimeoutSecs, keepAliveMax, contentFactories, this));
			} catch (Exception e) {
				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Failed waiting for connection.", e);
			}
		}
	}
	
}