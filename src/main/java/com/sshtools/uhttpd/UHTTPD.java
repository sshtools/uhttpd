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
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.ref.SoftReference;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * Simple HTTP/HTTPS server, configured using a fluent API.
 */
public class UHTTPD extends Thread implements Closeable {

	/**
	 * Selector that just matches everything. All handlers will
	 * be executed.
	 */
	public final static class AllSelector implements Selector {
		@Override
		public boolean matches(Transaction request) {
			return true;
		}
	}
	
	/**
	 * Something that provides a way to authenticate a given
	 * {@link Credential} and provide a {@link Principal}.
	 */
	public interface Authenticator<C extends Credential> {
		/**
		 *  Authenticate.
		 *
		 * @param credential the gather credentials.
		 * @return principal or empty if authentication failed
		 */
		Optional<Principal> authenticate(C credential);
	}

	/**
	 * Encapsulates a single HTTP connection. For every {@link SocketChannel}
	 * there will be a single instance of this client. The public
	 * API exposes methods to get at some of the lower level details.
	 * <p>
	 * The details of the HTTP protocol in use (e.g. HTTP 1.1,
	 * WebSocket etc) are delegated to the {@link WireProtocol}. For
	 * example {@link HTTP11WireProtocol}.
	 */
	public static final class Client implements Runnable, Closeable {

		final boolean cache;
		final Map<Selector, Handler> contentFactories;
		final boolean keepAlive;
		final int keepAliveMax;
		final int keepAliveTimeoutSecs;
		final Closeable server;
		final SocketChannel socket;

		boolean closed = false;
		int times = 0;
		WireProtocol wireProtocol;
		Charset charset = Charset.defaultCharset();

		Client(SocketChannel socket, boolean cache, boolean keepAlive, int keepAliveTimeoutSecs, int keepAliveMax,
				Map<Selector, Handler> contentFactories, Closeable server) throws IOException {
			this.socket = socket;
			this.cache = cache;
			this.keepAlive = keepAlive;
			this.keepAliveTimeoutSecs = keepAliveTimeoutSecs;
			this.keepAliveMax = keepAliveMax;
			this.contentFactories = contentFactories;
			this.server = server;

			wireProtocol = new HTTP11WireProtocol(this);
		}

		public final SocketChannel channel() {
			return socket;
		}

		public final Charset charset() {
			return charset;
		}

		public final Client charset(Charset charset) {
			this.charset = charset;
			return this;
		}

		/**
		 * Not public API
		 */
		@Override
		public final void close() throws IOException {
			if (!closed) {
				closed = true;
				try {
					socket.close();
				} catch (IOException ioe) {
				}
			}
		}

		/**
		 * Not public API
		 */
		@Override
		public final void run() {
			try {
				var client = socket.getLocalAddress();
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
						LOG.log(Level.DEBUG, "{0} connected to server", socket.getRemoteAddress());
						do {
							wireProtocol.transact();
							times++;
						} while (times < keepAliveMax);
					} catch (EOFException e) {
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

		public final WireProtocol wireProtocol() {
			return wireProtocol;
		}

	}

	/**
	 * Represents the content sent from the client, e.g.
	 * a form submission. Content is made up of multiple {@link Part}s.
	 */
	public interface Content {
		/**
		 * A convenience method to get a part that is a piece of {@link FormData} given it's name, throwing
		 * an exception if there is no such part.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream
		 * or parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default FormData asFormData(String name) {
			return formData(name).orElseThrow();
		}

		/**
		 * Get all of the {@link Part}s that make up this content.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream
		 * or a named part.
		 *
		 * @return parts
		 */
		Iterable<Part> asParts();

		/**
		 * Get the entire content as a stream.
		 * <p>
		 * This cannot be used if the content has already been retrieved as parts
		 * or name parts.
		 *
		 * @return as stream
		 */
		InputStream asStream();

		/**
		 * Get the overall content type (i.e. <code>Content-Type</strong> header) of this
		 * content. Individual parts will have different content types.
		 *
		 * @return content type
		 */
		Optional<String> contentType();

		/**
		 * A convenience method to get a part that is a piece of {@link FormData} given it's name.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream
		 * or parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default Optional<FormData> formData(String name) {
			return part(name, FormData.class);
		}

		/**
		 * Get a part given it's name and class.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream
		 * or parts.
		 *
		 * @param <P> type of part
		 * @param name part name
		 * @param clazz class of part
		 * @return part
		 */
		<P extends Part> Optional<P> part(String name, Class<P> clazz);

		/**
		 * Get the size of this content if known.
		 *
		 * @return size
		 */
		Optional<Long> size();
	}

	public interface Cookie {
		/**
	     * Returns the name of this cookie.
	     *
	     * @return The name of this cookie
	     */
	    String name();
	
	    /**
	     * Returns the value of "SameSite" for this cookie
	     * 
	     * @return same site of this cookie
	     */
	    Optional<SameSite> sameSite();

		/**
		 * Explicit date and time when this cookie expires.
		 * 
		 * @return cookie expires
		 */
		Optional<Date> expires();

		/**
	     * The value of this cookie.
	     *
	     * @return value of this cookie
	     */
	    String value();
	
	    /**
	     * The version of cookie.
	     */
	    CookieVersion version();
	
	    /**
	     * Domain of this cookie
	     *
	     * @return domain of this cookie
	     */
	    Optional<String> domain();
	
	    /**
	     * Path of this cookie
	     *
	     * @return path of this cookie
	     */
	    Optional<String> path();
	
	    /**
	     * The maximum age of this cook in seconds.
	     *
	     * @return the maximum age of this cookie
	     */
	    Optional<Long> maxAge();
	
	    /**
	     * Get if this cookie is secure.
	     *
	     * @return secure cookie
	     */
	    boolean secure();
	
	    /**
	     * HTTP usage only.
	     */
	    boolean httpOnly();
	
	}
	
	/**
	 * Use to build {@link Cookie} instances for setting on responses.
	 */

	public final static class CookieBuilder {
		
		final String name;
		CookieVersion version = CookieVersion.V1;
		boolean secure;
		boolean httpOnly;
		final String value;
		Optional<String> path = Optional.empty();
		Optional<String> domain = Optional.empty();
		Optional<Long> maxAge = Optional.empty();
		Optional<Date> expires = Optional.empty();
		Optional<SameSite> sameSite= Optional.empty();
		
		CookieBuilder(String name, String value) {
			this.name = name;
			this.value = value;
		}
		
		public CookieBuilder withVersion(CookieVersion version) {
			this.version = version;
			return this;
		}
		
		public CookieBuilder withSecure() {
			this.secure = true;
			return this;
		}
		
		public CookieBuilder withMaxAge(long maxAge) {
			this.maxAge =  Optional.of(maxAge);
			return this;
		}
		
		public CookieBuilder withSameSite(SameSite sameSite) {
			this.sameSite =  Optional.of(sameSite);
			return this;
		}
		
		public CookieBuilder withExpires(Date expires) {
			this.expires = Optional.of(expires);
			return this;
		}
		
		public CookieBuilder withExpires(Instant instant) {
			this.expires = Optional.of(new Date(instant.toEpochMilli()));
			return this;
		}
		
		public CookieBuilder withHttpOnly() {
			this.httpOnly = true;
			return this;
		}
		
		public CookieBuilder withPath(String path) {
			this.path = Optional.of(path);
			return this;
		}
		
		public CookieBuilder withDomain(String domain) {
			this.domain = Optional.of(domain);
			return this;
		}
		
		public Cookie build() {
			return new Cookie() {
				
				@Override
				public CookieVersion version() {
					return version;
				}
				
				@Override
				public String value() {
					return value;
				}
				
				@Override
				public boolean secure() {
					return secure;
				}
				
				@Override
				public Optional<String> path() {
					return path;
				}
				
				@Override
				public String name() {
					return name;
				}
				
				@Override
				public Optional<Long> maxAge() {
					return maxAge;
				}
				
				@Override
				public Optional<SameSite> sameSite() {
					return sameSite;
				}
				
				@Override
				public Optional<Date> expires() {
					return expires;
				}
				
				@Override
				public boolean httpOnly() {
					return httpOnly;
				}
				
				@Override
				public Optional<String> domain() {
					return domain;
				}
				
				@Override
				public String toString() {
					var b = new StringBuilder();
					b.append(name);
					b.append('=');
					b.append(value);
					path.ifPresent(p -> { 
						b.append("; Path=");
						b.append(p);
					});
					domain.ifPresent(p -> { 
						b.append("; Domain=");
						b.append(p);
					});
					maxAge.ifPresent(p -> { 
						b.append("; Max-Age=");
						b.append(p);
					});
					expires.ifPresent(p -> { 
						b.append("; Expires=");
						b.append(DateFormatHolder.formatFor(PATTERN_RFC1123).format(p));
					});
					if(secure) { 
						b.append("; Secure");
					}
					if(httpOnly) { 
						b.append("; HttpOnly");
					}
					sameSite.ifPresent(p -> { 
						b.append("; SameSite=");
						b.append(Character.toUpperCase(p.name().charAt(0)) + p.name().substring(1).toLowerCase());
					});
					
					return b.toString();
				}
			};
		}
	}
	
	/**
	 * Version of @{link {@link Cookie}.
	 */
	public enum CookieVersion {
		V1, V2
	}

	/**
	 * Selector that executes a {@link Handler} if all {@link Selector}s
	 * it contains match.
	 *
	 */
	public static final class CompoundSelector implements Selector {
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
	
	/**
	 * Represents some piece of information that can be used to
	 * authenticate a user.
	 */
	public interface Credential {
		/**
		 * Turn this {@link Credential} into a {@link Principal}
		 * if success its <code>true</code>, otherwise return an
		 * empty {@link Optional}.
		 *
		 * @param success whether authentication was successful or not
		 * @return a principal or empty
		 */
		Optional<Principal> result(boolean success);
	}

	/**
	 * A {@link Part} that represents a piece form data, as
	 * sent with a content type of <code>multipart/form-data</code>
	 */
	public final static class FormData implements TextPart {

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

		/**
		 * Get the content type of this part if known.
		 * 
		 * @return content type
		 */
		public final Optional<String> contentType() {
			return contentType;
		}

		/**
		 * Get the filename of this part, if the part is a file
		 * upload.
		 * 
		 * @return filename
		 */
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

	/**
	 * Interface to be implemented to handle any request received
	 * by the server. {@link Handler} is fundamental to UHTTPD.
	 */
	public interface Handler {
		void get(Transaction req) throws Exception;
	}

	/**
	 * Builds a {@link Handler} to support HTTP Basic Authentication.
	 * See {@link UHTTPD#httpBasicAuthentication(Authenticator)}.
	 */
	public final static class HttpBasicAuthentication {

		private Authenticator<UsernameAndPassword> authenticator;
		private Optional<String> realm = Optional.empty();

		HttpBasicAuthentication(Authenticator<UsernameAndPassword> authenticator) {
			this.authenticator = authenticator;
		}

		/**
		 * Builds the handler.
		 * 
		 * @return handler
		 * @throws UnknownHostException
		 * @throws IOException
		 */
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

		/**
		 * Set the realm to use.
		 * 
		 * @param realm realm
		 * @return this for chaining
		 */
		public HttpBasicAuthentication withRealm(String realm) {
			this.realm = Optional.of(realm);
			return this;
		}
	}

	/**
	 * Constants for HTTP methods.
	 */
	public enum Method {
		CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE
	}

	/**
	 * Select a handler based on its {@link Transaction#method()}. If the
	 * method matches, the handler will be executed.
	 *
	 */
	public static final class MethodSelector implements Selector {

		private List<Method> methods;

		public MethodSelector(Method... methods) {
			this.methods = Arrays.asList(methods);
		}

		@Override
		public boolean matches(Transaction request) {
			return methods.contains(request.method());
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

		private final String name;

		private final List<String> values;

		Named(String name, List<String> values) {
			super();
			this.name = name;
			this.values = values;
		}

		Named(String name, String value) {
			this(name, value == null ? Collections.emptyList() : Arrays.asList(value));
		}

		public boolean contains(String value) {
			return values.contains(value);
		}

		public boolean containsIgnoreCase(String value) {
			for (var n : values) {
				if (n.equalsIgnoreCase(value))
					return true;
			}
			return false;
		}

		public Named expand(String separator) {
			return new Named(name, Arrays.asList(asString().split(separator)).stream().map(s -> s.trim())
					.collect(Collectors.toList()));
		}

		@Override
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

		public List<String> values() {
			return Collections.unmodifiableList(values);
		}
	}

	public interface OnWebSocketClose {
		void closed(int code, String reason, WebSocket websocket);
	}

	public interface OnWebSocketData {
		void receive(ByteBuffer data, boolean finalFragment, WebSocket websocket);
	}

	public interface OnWebSocketText {
		void receive(String text, WebSocket websocket);
	}

	public interface OnWebSocketHandshake {
		String handshake(Transaction tx, String... protocols);
	}

	public interface OnWebSocketOpen {
		void open(WebSocket websocket);
	}

	public interface Part {
		String name();
	}

	public enum Protocol {
		HTTP_0, HTTP_1_0, HTTP_1_1, HTTP_2, HTTP_3;

		String text() {
			return "HTTP/" + (name().substring(5).replace('_', '.'));
		}
	}

	/**
	 * Select a {@link Handler} based on its {@link Transaction#path()}, i.e. URI.
	 * If the URI matches, the handler will be executred.
	 *
	 */
	public static final class RegularExpressionSelector implements Selector {

		private Pattern pattern;

		public RegularExpressionSelector(String regexp) {
			pattern = Pattern.compile(regexp);
		}

		@Override
		public boolean matches(Transaction req) {
			var path = req.path().toString();
			return pattern.matcher(path).matches();
		}

	}
	
	/**
	 * Can be used with {@link Transaction#respond} to supply response
	 * content piece by piece. Each call you are expected to fill a {@link ByteBuffer}
	 * until there is no more content, when the buffer should be returned with a zero
	 * limit. 
	 * 
	 */
	public interface Responder {
		/**
		 * Supply some more data for the response. Upon invocation, the
		 * byte buffer will be reset. If there is content, before exit 
		 * it should NOT be {@link ByteBuffer#flip()}ped so that {@link ByteBuffer#position()} is greater than zero.
		 * <p>
		 * If there is no more content, the {@link ByteBuffer#position()} should be zero. So
		 * if you just don't write anything to the buffer this will be the case.
		 * <p>
		 * If the size and type of the content is known, {@link Transaction#responseLength(long)} and
		 * {@link Transaction#responseType(String)} should be set.
		 *   
		 * @param buffer buffer to fill
		 */
		void supply(ByteBuffer buffer);
	}

	/**
	 * The "Same Site" attribute used by {@link Cookie} to 
	 * mitigate CSRF attacks. Currently a draft. https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-07
	 */
	public enum SameSite {
		STRICT, LAX, NONE;
	}

	/**
	 * A selector decides if a {@link Handler} applies
	 * to a given {@link Transaction}, e.g. should a handler
	 * handle a GET request for a certain URI.
	 */
	public interface Selector {
		boolean matches(Transaction request);
	}

	/**
	 * Builder to create a new instance of the main server,
	 * an {@link UHTTPD} instance.
	 */
	public final static class ServerBuilder {
		private int backlog = 10;
		private boolean cache = true;
		private boolean daemon;
		private Map<Selector, Handler> handlers = new LinkedHashMap<>();
		private Optional<InetAddress> httpAddress = Optional.empty();
		private Optional<Integer> httpPort = Optional.of(8080);
		private Optional<InetAddress> httpsAddress = Optional.empty();
		private Optional<Integer> httpsPort = Optional.empty();
		private boolean keepAlive = true;
		private int keepAliveMax = 100;
		private int keepAliveTimeoutSecs = 15;
		private Optional<char[]> keyPassword = Optional.empty();
		private String keyStoreAlias = "uhttpd";
		private Optional<Path> keyStoreFile = Optional.empty();
		private Optional<char[]> keyStorePassword = Optional.empty();
		private String threadName = "UHTTPD";
		private Optional<Integer> threads = Optional.empty();

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

		public ServerBuilder handle(String regexp, Handler... handler) {
			return handle(new RegularExpressionSelector(regexp), handler);
		}

		public ServerBuilder post(String regexp, Handler... handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.POST), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder webSocket(String regexp, WebSocketHandler handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.GET), new RegularExpressionSelector(regexp)),
					handler);
		}

		public ServerBuilder withBacklog(int backlog) {
			this.backlog = backlog;
			return this;
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups, Handler... handler) {
			return withClasspathResources(regexpWithGroups, "", handler);
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader,
				String prefix, Handler... handler) {
			var l = new ArrayList<Handler>();
			l.add(new ClasspathResources(regexpWithGroups, loader, prefix));
			l.addAll(Arrays.asList(handler));
			handle(new RegularExpressionSelector(regexpWithGroups), l.toArray(new Handler[0]));
			return this;
		}

		public ServerBuilder withClasspathResources(String regexpWithGroups, String prefix, Handler... handler) {
			return withClasspathResources(regexpWithGroups,
					Optional.ofNullable(Thread.currentThread().getContextClassLoader()), prefix, handler);
		}

		public ServerBuilder withFileResources(String regexpWithGroups, Path root, Handler... handler) {
			var l = new ArrayList<Handler>();
			l.add(new FileResources(regexpWithGroups, root));
			l.addAll(Arrays.asList(handler));
			handle(new RegularExpressionSelector(regexpWithGroups), l.toArray(new Handler[0]));
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

		public ServerBuilder withKeepaliveMax(int keepAliveMax) {
			this.keepAliveMax = keepAliveMax;
			return this;
		}

		public ServerBuilder withKeepaliveTimeoutSecs(int keepAliveTimeoutSecs) {
			this.keepAliveTimeoutSecs = keepAliveTimeoutSecs;
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

		public ServerBuilder withoutCache() {
			this.cache = false;
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

		public ServerBuilder withoutKeepalive() {
			this.keepAlive = false;
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

	public enum Status {

		BAD_REQUEST(400, "Bad Request"), CONTINUE(100, "Continue"), FORBIDDEN(403, "Forbidden"), FOUND(302, "Found"),
		INTERNAL_SERVER_ERROR(500, "Not Found"), MOVED_PERMANENTLY(301, "Moved Permanently"),
		NOT_FOUND(404, "Not Found"), NOT_IMPLEMENTED(501, "Not Implemented"), OK(200, "OK"),
		SERVICE_UNAVAILABLE(503, "Service Unavailable"), SWITCHING_PROTOCOLS(101, "Switching Protocols"),
		UNAUTHORIZED(401, "Unauthorized");

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

	public interface TextPart extends Part {

		default BigDecimal asBigDecimal() {
			return value().map(v -> new BigDecimal(v)).orElseThrow();
		}

		default boolean asBoolean() {
			return value().map(v -> Boolean.valueOf(v)).orElseThrow();
		}

		default byte asByte() {
			return value().map(v -> Byte.parseByte(v)).orElseThrow();
		}

		default char asChar() {
			return value().map(v -> v.charAt(0)).orElseThrow();
		}

		default double asDouble() {
			return value().map(v -> Double.parseDouble(v)).orElseThrow();
		}

		default float asFloat() {
			return value().map(v -> Float.parseFloat(v)).orElseThrow();
		}

		default int asInt() {
			return value().map(v -> Integer.parseInt(v)).orElseThrow();
		}

		default long asLong() {
			return value().map(v -> Long.parseLong(v)).orElseThrow();
		}

		default Reader asReader() {
			return new StringReader(asString());
		}

		default short asShort() {
			return value().map(v -> Short.parseShort(v)).orElseThrow();
		}

		default InputStream asStream() {
			return new ByteArrayInputStream(asString().getBytes());
		}

		default String asString() {
			return value().orElseThrow();
		}

		Optional<String> value();
	}

	public final static class Transaction {

		private final Client client;

		private Optional<Status> code = Optional.empty();
		private Supplier<Optional<Content>> contentSupplier;
		private final Map<String, Named> incomingHeaders = new LinkedHashMap<>();
		private final Map<String, String> incomingCookies = new LinkedHashMap<>();
		private final List<String> matches = new ArrayList<>();
		private final Method method;
		private Optional<String> outgoingContentType = Optional.empty();
		private final Map<String, Named> outgoingHeaders = new LinkedHashMap<>();
		private final Map<String, Cookie> outgoingCookies = new LinkedHashMap<>();
		private final Map<String, Named> parameters = new LinkedHashMap<>();
		private final Path path;
		private Optional<Principal> principal = Optional.empty();
		private final Protocol protocol;
		private Optional<Object> response = Optional.empty();
		private Optional<Responder> responder = Optional.empty();
		private Optional<Long> responseLength = Optional.empty();
		private Optional<String> responseText = Optional.empty();
		private Optional<Selector> selector = Optional.empty();
		private final String urlHost;

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

		public void authenticate(Principal principal) {
			this.principal = Optional.of(principal);
		}

		public boolean authenticated() {
			return principal.isPresent();
		}

		public Client client() {
			return client;
		}

		public void error(Exception ise) {
			responseCode(Status.INTERNAL_SERVER_ERROR);
			if (ise.getMessage() != null)
				responseText(ise.getMessage());
			responseType("text/plain");
			responseLength = Optional.empty();

		}

		public Transaction found(String location) {
			responseCode(Status.FOUND);
			header("Location", location == null ? "/" : location);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public boolean hasResponseHeader(String name) {
			return outgoingHeaders.containsKey(name);
		}

		public String header(String name) {
			return headerOr(name).orElseThrow();
		}

		public Transaction cookie(Cookie cookie) {
			outgoingCookies.put(cookie.name(), cookie);
			return this;
		}

		public Transaction cookie(String name, String value) {
			return cookie(UHTTPD.cookie(name,value).build());
		}

		public String cookie(String name) {
			return cookieOr(name).orElseThrow();
		}

		public Transaction header(String name, String value) {
			outgoingHeaders.put(name.toLowerCase(), new Named(name.toLowerCase(), value));
			return this;
		}

		public Optional<String> headerOr(String name) {
			return headersOr(name).map(h -> h.value().get());
		}

		public Optional<String> cookieOr(String name) {
			return Optional.ofNullable(incomingCookies.get(name));
		}

		public final List<Named> headers() {
			return Collections.unmodifiableList(new ArrayList<>(incomingHeaders.values()));
		}

		public Named headers(String name) {
			return headersOr(name).orElseThrow();
		}

		public Optional<Named> headersOr(String name) {
			return incomingHeaders.values().stream().filter(h -> h.name().equals(name.toLowerCase()))
					.map(h -> Optional.of(h)).reduce((f, s) -> f).orElse(Optional.empty());
		}

		public String hostname() {
			var hdr = headerOr(HDR_HOST);
			return hdr.isPresent() ? hdr.get() : urlHost;
		}

		public List<String> matches() {
			return Collections.unmodifiableList(matches);
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

		public Named parameter(String name) {
			return parameterOr(name).orElseThrow();
		}

		public Iterable<String> parameterNames() {
			return parameters.keySet();
		}

		public Optional<Named> parameterOr(String name) {
			return Optional.ofNullable(parameters.get(name));
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

		public Content request() {
			return contentSupplier.get().orElseThrow();
		}

		public Optional<Content> requestOr() {
			return contentSupplier.get();
		}

		public Transaction responder(Responder responder) {
			this.responder = Optional.of(responder);
			return this;
		}

		public Transaction responder(String responseType, Responder responder) {
			responseType(responseType);
			this.responder = Optional.of(responder);
			return this;
		}

		public Transaction response(Object response) {
			this.response = Optional.of(response);
			return this;
		}

		public Transaction response(String responseType, Object response) {
			responseType(responseType);
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

		public Transaction responseLength(long responseLength) {
			this.responseLength = responseLength == -1 ? Optional.empty() : Optional.of(responseLength);
			return this;
		}

		public Transaction responseText(String text) {
			this.responseText = Optional.of(text);
			return this;
		}

		public Transaction responseType(String contentType) {
			outgoingContentType = Optional.ofNullable(contentType);
			return this;
		}

		public Selector selector() {
			return selector.orElseThrow();
		}

		public Optional<Selector> selectorOr() {
			return selector;
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
	}

	public interface UsernameAndPassword extends Credential {
		char[] password();

		@Override
		default Optional<Principal> result(boolean success) {
			if (success) {
				return Optional.of(new Principal() {
					@Override
					public String getName() {
						return username();
					}
				});
			} else
				return Optional.empty();
		}

		String username();
	}

	public interface WebSocket extends Closeable {
		Client client();

		String protocol();

		default void send(ByteBuffer data) throws UncheckedIOException {
			fragment(data, true);
		}

		void fragment(ByteBuffer data, boolean finalFrame) throws UncheckedIOException;

		void send(String data) throws UncheckedIOException;

		int version();
	}

	public static final class WebSocketBuilder {
		private Optional<OnWebSocketClose> onClose = Optional.empty();
		private Optional<OnWebSocketData> onData = Optional.empty();
		private Optional<OnWebSocketText> onText = Optional.empty();
		private Optional<OnWebSocketHandshake> onHandshake = Optional.empty();
		private Optional<OnWebSocketOpen> onOpen = Optional.empty();
		private int maxTextPayloadSize = 32768;
		private boolean mask = true;

		public WebSocketHandler build() {
			return new WebSocketHandler(this);
		}

		public WebSocketBuilder withoutMask() {
			this.mask = false;
			return this;
		}

		public WebSocketBuilder withMaxTextPayloadSize(int maxTextPayloadSize) {
			this.maxTextPayloadSize = maxTextPayloadSize;
			return this;
		}

		public WebSocketBuilder onClose(OnWebSocketClose onClose) {
			this.onClose = Optional.of(onClose);
			return this;
		}

		public WebSocketBuilder onData(OnWebSocketData onData) {
			this.onData = Optional.of(onData);
			return this;
		}

		public WebSocketBuilder onText(OnWebSocketText onText) {
			this.onText = Optional.of(onText);
			return this;
		}

		public WebSocketBuilder onHandshake(OnWebSocketHandshake onHandshake) {
			this.onHandshake = Optional.of(onHandshake);
			return this;
		}

		public WebSocketBuilder onOpen(OnWebSocketOpen onOpen) {
			this.onOpen = Optional.of(onOpen);
			return this;
		}

	}

	public static final class WebSocketHandler implements Handler {

		/**
		 * Order is important!
		 */
		enum OpCode {
			CONTINUATION, TEXT, BINARY, RSV_NON_CONTROL_1, RSV_NON_CONTROL_2, RSV_NON_CONTROL_3, RSV_NON_CONTROL_4,
			RSV_NON_CONTROL_5, CLOSE, PING, PONG, RSV_CONTROL_1, RSV_CONTROL_2, RSV_CONTROL_3, RSV_CONTROL_4,
			RSV_CONTROL_5,
		}

		private abstract class AbstractIncomingMessage {

			abstract void read(WebSocketImpl ws, WebSocketFrame frame, SocketChannel channel) throws IOException;

		}

		private final class CloseMessage extends AbstractIncomingMessage {

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, SocketChannel channel) throws IOException {
				if (!frame.fin)
					throw new IllegalStateException("Control frames must not be fragment.");
				var payload = frame.payload;
				var code = Short.toUnsignedInt(payload.getShort());
				var dec = ws.client().charset().newDecoder(); // todo reuse?
				var out = dec.decode(payload);
				var text = out.toString();
				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Received websocket close message. Reason {0}. {1}", code, text);
				onClose.ifPresent(c -> c.closed(code, text, ws));
			}
		}

		private final class PingMessage extends AbstractIncomingMessage {

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, SocketChannel channel) throws IOException {
				if (!frame.fin)
					throw new IllegalStateException("Control frames must not be fragment.");
				var pongFrame = new WebSocketFrame(OpCode.PONG, frame.payload, true, frame.mask, frame.key);
				pongFrame.write(channel);
			}
		}

		private class BinaryMessage extends AbstractIncomingMessage {

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, SocketChannel channel) {
				onData.ifPresent(c -> c.receive(frame.payload, frame.fin, ws));
			}
		}

		private class TextMessage extends AbstractIncomingMessage {

			CharsetDecoder dec;
			CharBuffer out;

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, SocketChannel channel) {

				if (dec == null) {
					dec = ws.client().charset().newDecoder(); // todo reuse?
				}

				var in = frame.payload;

				if (out == null) {
					int n = (int) (in.remaining() * dec.averageCharsPerByte());
					out = CharBuffer.allocate(n);
				}

				int n = out.capacity();

				if ((n == 0) && (in.remaining() == 0)) {
					if (frame.fin) {
						out.flip();
						onText.ifPresent(c -> c.receive(out.toString(), ws));
					}
					return;
				}
				dec.reset();
				try {
					for (;;) {
						CoderResult cr = in.hasRemaining() ? dec.decode(in, out, true) : CoderResult.UNDERFLOW;
						if (cr.isUnderflow())
							cr = dec.flush(out);

						if (cr.isUnderflow())
							break;
						if (cr.isOverflow()) {
							n = 2 * n + 1; // Ensure progress; n might be 0!
							CharBuffer o = CharBuffer.allocate(n);
							out.flip();
							o.put(out);
							out = o;
							continue;
						}
						cr.throwException();
					}
					if (frame.fin) {
						out.flip();
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Receive websocket text: {0}", out.toString());
						onText.ifPresent(c -> c.receive(out.toString(), ws));
					}
				} catch (CharacterCodingException cce) {
					throw new IllegalStateException("Failed to decode text message.", cce);
				}
			}

		}

		private final class WebSocketFrame {

			private static final long MAX_PAYLOAD_SIZE = Integer.MAX_VALUE - 8; // TODO make configurable and much
																				// smaller

			ByteBuffer buffer = ByteBuffer.allocate(14); // enough for header
			boolean fin, rsv1, rsv2, rsv3, mask;
			byte[] key;
			OpCode opCode;
			ByteBuffer payload; // TODO reuse buffer

			WebSocketFrame() {
			}

			WebSocketFrame(OpCode opCode, ByteBuffer payload, boolean fin) {
				this(opCode, payload, fin, WebSocketHandler.this.mask, WebSocketHandler.this.mask ? makeKey() : null);
			}

			private static byte[] makeKey() {
				// TODO optimise
				var b = new byte[4];
				new SecureRandom().nextBytes(b);
				return b;
			}

			WebSocketFrame(OpCode opCode, ByteBuffer payload, boolean fin, boolean mask, byte[] key) {
				this.opCode = opCode;
				this.payload = payload;
				this.fin = fin;
				this.mask = mask;
				this.key = key;
				if (mask) {
					debugByteBuffer("Before masking", payload);
					var len = payload.limit();
					for (int i = payload.position(); i < len; i++) {
						payload.put(i, (byte) (payload.get(i) ^ key[(i - payload.position()) % 4]));
					}
				}
			}

			@Override
			public String toString() {
				return "WebSocketFrame [fin=" + fin + ", rsv1=" + rsv1 + ", rsv2=" + rsv2 + ", rsv3=" + rsv3 + ", mask="
						+ mask + ", opCode=" + opCode + ", buffer=" + buffer + ", key=" + key + ", payload=" + payload
						+ "]";
			}

			void read(SocketChannel channel) throws IOException {
				buffer.clear();
				channel.read(buffer);
				buffer.flip();

				if (LOG.isLoggable(Level.TRACE))
					debugByteBuffer("Frame", buffer);

				var b1 = buffer.get();
				if (b1 == -1)
					throw new EOFException();

				fin = (b1 & 0x80) != 0;
				rsv1 = (b1 & 0x40) != 0;
				rsv2 = (b1 & 0x20) != 0;
				rsv3 = (b1 & 0x10) != 0;

				if (rsv1 || rsv2 || rsv3) {
//					 RSV1, RSV2, RSV3:  1 bit each
//
//				      MUST be 0 unless an extension is negotiated that defines meanings
//				      for non-zero values.  If a nonzero value is received and none of
//				      the negotiated extensions defines the meaning of such a nonzero
//				      value, the receiving endpoint MUST _Fail the WebSocket
//				      Connection_
					throw new IOException("Extensions are not supported.");
				}
				opCode = OpCode.values()[b1 & 0xf];

				b1 = buffer.get();
				if (b1 == -1)
					throw new EOFException();
				mask = (b1 & 0x80) != 0;
				var longPayloadLength = (long) (b1 & 0x7f);
				if (longPayloadLength > 126) {
					longPayloadLength = buffer.getLong();
				} else if (longPayloadLength > 125) {
					longPayloadLength = Short.toUnsignedInt(buffer.getShort());
				}
				if (longPayloadLength > MAX_PAYLOAD_SIZE)
					longPayloadLength = MAX_PAYLOAD_SIZE;

				if (mask) {
					key = new byte[4];
					buffer.get(key);
				}

				if (mask)
					payload = ByteBuffer.allocate((int) longPayloadLength);
				else
					payload = ByteBuffer.allocateDirect((int) longPayloadLength);
				payload.put(buffer);
				channel.read(payload);
				payload.flip();

				if (mask) {
					var arr = payload.array();
					var len = payload.limit();
					for (int i = 0; i < len; i++)
						arr[i] = (byte) (arr[i] ^ key[i % 4]);
				}
				if (LOG.isLoggable(Level.TRACE))
					debugByteBuffer("Payload", payload);
			}

			void write(SocketChannel channel) throws IOException {

				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Sending frame: {0}", this);

				buffer.clear();

				var b1 = fin ? (byte) 0x80 : (byte) 0x0;
				b1 = (byte) (b1 | (rsv1 ? 1 << 6 : 0));
				b1 = (byte) (b1 | (rsv2 ? 1 << 5 : 0));
				b1 = (byte) (b1 | (rsv3 ? 1 << 4 : 0));
				b1 = (byte) (b1 | (opCode.ordinal() & 0x0f));
				buffer.put(b1);

				b1 = mask ? (byte) 0x80 : (byte) 0x0;
				var payloadLength = payload.limit();
				if (payloadLength > 125) {
					if (payloadLength > Short.MAX_VALUE * 2) {
						b1 = (byte) (b1 | 127);
						buffer.put(b1);
						buffer.putLong(payloadLength);
					} else {
						b1 = (byte) (b1 | 126);
						buffer.put(b1);
						buffer.putShort((short) payloadLength);
					}
				} else {
					b1 = (byte) (b1 | (payloadLength & 0x7f));
					buffer.put(b1);
				}

				if (mask) {
					if (key.length != 4)
						throw new IllegalArgumentException("Key must be 4 bytes.");
					buffer.put(key);
				}
				buffer.flip();

				if (LOG.isLoggable(Level.TRACE)) {
					debugByteBuffer("Frame", buffer);
					debugByteBuffer("Payload", payload);
				}

				channel.write(buffer);
				channel.write(payload);
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
			public Client client() {
				return client;
			}

			@Override
			public void close() throws IOException {
				client.close();
			}

			@Override
			public String protocol() {
				return selectedProtocol;
			}

			@Override
			public void fragment(ByteBuffer data, boolean finalPacket) {
				var frame = new WebSocketFrame(OpCode.BINARY, data, finalPacket);
				try {
					frame.write(client.channel());
				} catch (IOException e) {
					throw new UncheckedIOException("Failed to send websocket text.", e);
				}
			}

			@Override
			public void send(String data) throws UncheckedIOException {
				var enc = client.charset.newEncoder();
				var buf = CharBuffer.wrap(data.toCharArray());
				try {
					var payload = enc.encode(buf);
					while (payload.hasRemaining()) {
						var limitWas = payload.limit();
						if (payload.remaining() > maxTextPayloadSize) {
							payload.limit(Math.min(payload.capacity(), payload.position() + maxTextPayloadSize));
						}
						var fin = payload.limit() == limitWas;
						var frame = new WebSocketFrame(OpCode.TEXT, payload, fin);
						try {
							frame.write(client.channel());
						} catch (IOException e) {
							throw new UncheckedIOException("Failed to send websocket text.", e);
						}
						payload.limit(limitWas);
					}
				} catch (CharacterCodingException cce) {
					throw new UncheckedIOException("Failed to encode text.", cce);
				}
			}

			@Override
			public int version() {
				return version;
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
				boolean closed = false;
				try {
					var channel = ws.client.channel();
					var frame = new WebSocketFrame();
					AbstractIncomingMessage lastMessage = null;
					while (true) {
						frame.read(channel);
						if(closed)
							throw new IllegalStateException("Got another message after a close message.");
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Frame: {0}", frame);
						switch (frame.opCode) {
						case CONTINUATION:
							if (lastMessage == null)
								throw new IllegalStateException("Received CONTINUATION before other op code.");
							lastMessage.read(ws, frame, channel);
							break;
						case PING:
							lastMessage = new PingMessage();
							lastMessage.read(ws, frame, channel);
							break;
						case CLOSE:
							lastMessage = new CloseMessage();
							lastMessage.read(ws, frame, channel);
							closed = true;
							break;
						case TEXT:
							lastMessage = new TextMessage();
							lastMessage.read(ws, frame, channel);
							break;
						case BINARY:
							lastMessage = new BinaryMessage();
							lastMessage.read(ws, frame, channel);
							break;
						default:
							throw new UnsupportedOperationException(frame.opCode + " is not supported.");
						}
						if (frame.fin)
							lastMessage = null;
					}
				} finally {
					if(!closed)
						onClose.ifPresent(h -> h.closed(1006, "Unexpected close.", ws));
				}
			}
		}

		private static final int SUPPORTED_WEBSOCKET_VERSION = 13;

		private final Optional<OnWebSocketClose> onClose;

		private final Optional<OnWebSocketData> onData;
		private final Optional<OnWebSocketText> onText;
		private final Optional<OnWebSocketHandshake> onHandshake;
		private final Optional<OnWebSocketOpen> onOpen;
		private final int maxTextPayloadSize;
		private final boolean mask;

		public WebSocketHandler(WebSocketBuilder builder) {
			this.mask = builder.mask;
			this.onData = builder.onData;
			this.onText = builder.onText;
			this.onClose = builder.onClose;
			this.onOpen = builder.onOpen;
			this.onHandshake = builder.onHandshake;
			this.maxTextPayloadSize = builder.maxTextPayloadSize;
		}

		@Override
		public void get(Transaction req) throws Exception {
			if (req.headersOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").contains("Upgrade")
					&& req.headerOr(HDR_UPGRADE).orElse("").equalsIgnoreCase("websocket")) {
				// TODO https://en.wikipedia.org/wiki/WebSocket

				// TODO origin check

				var key = req.header("sec-websocket-Key");
				var proto = req.headersOr("sec-websocket-protocol");
				var version = req.headers("sec-websocket-version").asInt();
				if (version > SUPPORTED_WEBSOCKET_VERSION) {
					req.header("sec-websocket-version", String.valueOf(SUPPORTED_WEBSOCKET_VERSION));
					req.responseCode(Status.BAD_REQUEST);
					return;
				}
				var hasher = MessageDigest.getInstance("SHA-1");
				var responseKeyData = key + WEBSOCKET_UUID;
				var responseKeyBytes = responseKeyData.getBytes("UTF-8");
				var responseKey = Base64.getEncoder().encodeToString(hasher.digest(responseKeyBytes));
				var selectedProtocol = onHandshake.isPresent()
						? onHandshake.get().handshake(req, proto.get().expand(",").values().toArray(new String[0]))
						: "";
				var client = req.client();

				var ws = new WebSocketImpl(client, selectedProtocol, version);

				req.responseCode(Status.SWITCHING_PROTOCOLS);
				req.header(HDR_CONNECTION, "Upgrade");
				req.header(HDR_UPGRADE, "websocket");
				if (!selectedProtocol.equals(""))
					req.header("sec-websocket-protocol", selectedProtocol);
				req.header("sec-websocket-accept", responseKey);

				client.wireProtocol = new WebSocketProtocol(ws);
			}
		}

		void debugByteBuffer(String type, ByteBuffer buf) {
			var b = new StringBuilder(type);
			b.append("---- Packet dump ----\r\n");
			b.append(buf.toString());
			b.append("\r\n");
			for (int i = buf.position(); i < buf.limit(); i++) {
				b.append(String.format(" %02x", Byte.toUnsignedInt(buf.get(i))));
			}
			b.append("\r\nBinary:");
			for (int i = buf.position(); i < buf.limit(); i++) {
				b.append(" " + String.format("%8s", Integer.toBinaryString(Byte.toUnsignedInt(buf.get(i)))).replace(' ',
						'0'));
			}
			b.append("\r\nDec   :");
			for (int i = buf.position(); i < buf.limit(); i++) {
				b.append(String.format(" %03d", Byte.toUnsignedInt(buf.get(i))));
			}
			b.append("\r\nChar  :");
			for (int i = buf.position(); i < buf.limit(); i++) {
				var v = Byte.toUnsignedInt(buf.get(i));
				b.append(String.format(" %s", v > 31 && v < 256 ? Character.toString(v) : "?"));
			}
			b.append("\r\n---------------------");
			LOG.log(Level.TRACE, b.toString());
		}

	}

	public interface WireProtocol {

		void transact() throws IOException;
	}

	static final class HTTP11WireProtocol implements WireProtocol {

		final Client client;
		final BufferedReader reader;
		final PrintWriter writer;

		HTTP11WireProtocol(Client client) {
			this.client = client;
			reader = new BufferedReader(Channels.newReader(client.channel(), client.charset));
			writer = new PrintWriter(Channels.newWriter(client.channel(), client.charset));
		}

		@Override
		public void transact() throws IOException {
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
			if (LOG.isLoggable(Level.DEBUG))
				LOG.log(Level.DEBUG, "HTTP IN: {0}", line);
			req.contentSupplier = new Supplier<>() {

				private boolean asNamedParts;
				private boolean asParts;
				private boolean asStream;
				private Optional<Content> content;
				private List<Part> parts;

				@Override
				public Optional<Content> get() {
					if (content == null) {
						content = Optional.ofNullable(new Content() {
							@Override
							public Iterable<Part> asParts() {
								if (asStream || asNamedParts) {
									throw new IllegalStateException("Already have content as stream or named parts.");
								}
								asParts = true;
								return asPartsImpl();
							}

							@Override
							public InputStream asStream() {
								if (asParts || asNamedParts)
									throw new IllegalStateException("Already have content as named or iterated parts.");
								asStream = true;
								return Channels.newInputStream(client.channel());
							}

							@Override
							public Optional<String> contentType() {
								return req.headerOr(HDR_CONTENT_TYPE);
							}

							@SuppressWarnings("unchecked")
							@Override
							public <P extends Part> Optional<P> part(String name, Class<P> clazz) {
								if (asStream || asParts) {
									throw new IllegalStateException(
											"Already have content as stream or iterated parts.");
								}
								for (var part : asPartsImpl()) {
									if (part.name().equals(name))
										return (Optional<P>) Optional.of(part);
								}

								return Optional.empty();
							}

							@Override
							public Optional<Long> size() {
								return req.headersOr(HDR_CONTENT_LENGTH).map(o -> o.asLong());
							}

							Iterable<Part> asPartsImpl() {
								if (parts == null) {
									parts = new ArrayList<>();
									return new Iterable<>() {
										@Override
										public Iterator<Part> iterator() {
											var it = iteratorImpl(reader);
											return new Iterator<>() {

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
														content.containsKey("boundary")
																? content.get("boundary").asString()
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
					LOG.log(Level.TRACE, "HTTP IN: {0}", line);
				var nvp = Named.parseHeader(line);
				req.incomingHeaders.put(nvp.name, nvp);
			}

			var close = !client.keepAlive || Protocol.HTTP_1_1.compareTo(proto) < 0
					|| req.headersOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").containsIgnoreCase("close");

			if (proto.compareTo(Protocol.HTTP_1_0) > 0) {
				req.headerOr(HDR_HOST).orElseThrow();
			}
			
			req.headersOr(HDR_COOKIE).ifPresent(c -> {
				for(var val : c.values()) {
					var spec = Named.parseSeparatedStrings(val);
					for(var cookie : spec.values()) {
						req.incomingCookies.put(cookie.name(), cookie.asString());
					}
				}
			});

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

			if (!req.code.isEmpty() && !req.response.isPresent() && !req.responder.isPresent()) {
				req.notFound();
			}

			respond(req, close);

			client.socket.socket().setSoTimeout(client.keepAliveTimeoutSecs * 1000);
		}

		private void flush() throws IOException {
			writer.flush();
		}

		private void newline() throws IOException {
			writer.append("\r\n");
			if (LOG.isLoggable(Level.TRACE))
				LOG.log(Level.TRACE, "HTTP OUT: <newline>");
		}

		private void print(Object text) throws IOException {
			if (LOG.isLoggable(Level.TRACE))
				LOG.log(Level.TRACE, "HTTP OUT: {0}", text);
			writer.append(text.toString());
		}

		private void println(Object text) throws IOException {
			print(text);
			newline();
		}

		private void respond(Transaction tx, boolean closed) throws IOException {

			var status = tx.code.orElse(Status.OK);
			var close = false;

			if (status.getCode() >= 300)
				close = true;

			print(tx.protocol().text());
			print(" ");
			print(status.code);
			print(" ");
			print(tx.responseText.orElse(status.getText()));
			newline();

			if (LOG.isLoggable(Level.DEBUG) && !LOG.isLoggable(Level.TRACE))
				LOG.log(Level.DEBUG, "HTTP OUT: {0} {1} {2}", tx.protocol().text(), status.code,
						tx.responseText.orElse(status.getText()));

			var responseLength = tx.responseLength;
			byte[] responseData = null;

			/* Do our best to get some kind of content length so keep alive works */
			if (!tx.responder.isPresent() && tx.response.isPresent()) {
				var resp = tx.response.get();
				if (resp instanceof ByteBuffer) {
					responseLength = Optional.of((long) ((ByteBuffer) resp).remaining());
				} else if (resp instanceof ByteBuffer) {
					responseLength = Optional.of((long) ((ByteBuffer)resp).remaining());
				} else if (resp instanceof byte[]) {
					responseData = (byte[]) resp;
					responseLength = Optional.of((long) ((byte[])responseData).length);
				} else if (!(resp instanceof InputStream) && !(resp instanceof Reader)) {
					responseData = String.valueOf(resp).getBytes();
					responseLength = Optional.of((long) ((byte[])responseData).length);
				}
			}

			if (responseLength.isPresent()) {
				print(HDR_CONTENT_LENGTH);
				print(": ");
				print(responseLength.get());
				newline();
			} /*
				 * else { close = true; }
				 */

			if (!tx.hasResponseHeader(HDR_CONNECTION)) {
				if (close && tx.protocol.compareTo(Protocol.HTTP_2) < 0) {
					print(HDR_CONNECTION);
					println(": close");
				} else if (tx.protocol.compareTo(Protocol.HTTP_1_0) > 0
						&& tx.protocol.compareTo(Protocol.HTTP_2) < 0) {
					print(HDR_CONNECTION);
					println(": keep-alive");
				}
			}

			if (tx.outgoingContentType.isPresent()) {
				print(HDR_CONTENT_TYPE);
				print(": ");
				print(tx.outgoingContentType.get());
				newline();
			}
			
			for (var nvp : tx.outgoingHeaders.values()) {
				print(nvp.name());
				print(": ");
				print(nvp.value().orElse(""));
				newline();
			}
			
			for(var cookie : tx.outgoingCookies.values()) {
				print(HDR_SET_COOKIE);
				print(": ");
				print(cookie);
				newline();
			}
			
			if (!client.cache) {
				print(HDR_CACHE_CONTROL);
				println(": no-cache");
			}
			newline();
			flush();
			if (tx.responder.isPresent()) {
				var buffer = ByteBuffer.allocateDirect(32768); // TODO configurable
				do {
					buffer.clear();
					tx.responder.get().supply(buffer);
					if(buffer.position() > 0) {
						buffer.flip();
						client.channel().write(buffer);
					}
				} while(buffer.position() > 0);
			}
			else if (tx.response.isPresent()) {
				var resp = tx.response.get();
				if (resp instanceof InputStream) {
					try (var in = (InputStream) resp) {
						in.transferTo(Channels.newOutputStream(client.channel()));
					}
				} else if (resp instanceof Reader) {
					try (var in = (Reader) resp) {
						in.transferTo(writer);
					}
				}  else if(resp instanceof ByteBuffer) {
					client.channel().write((ByteBuffer)resp);
				}
				else {
					client.channel().write(ByteBuffer.wrap(responseData));
				}
			}
			flush();
			if (close)
				throw new EOFException();
		}
	}

	private final static class ClasspathResources implements Handler {

		private Optional<ClassLoader> loader;
		private final String prefix;
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

	private final static class FileResources implements Handler {

		private final Pattern regexpWithGroups;
		private final Path root;

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

	private final static class MultipartFormDataPartIterator implements Iterator<Part> {

		String boundary;
		StringBuilder buffer = new StringBuilder(256);
		StringBuilder content;
		String contentDisposition;
		String contentType;
		boolean end;
		FormData next;

		long read;
		final Reader reader;
		final long size;

		MultipartFormDataPartIterator(Reader reader, String boundary, long size) {
			this.reader = reader;
			this.size = size;
			this.boundary = boundary;
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

	}

	private final static class URLEncodedFormDataPartIterator implements Iterator<Part> {

		StringBuilder buffer = new StringBuilder(256);
		Part next;
		long read;
		Reader reader;
		long size;

		URLEncodedFormDataPartIterator(Reader reader, long size) {
			this.reader = reader;
			this.size = size;
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

		void checkNext() {
			if (next == null) {
				char ch;
				buffer.setLength(0);

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
	}

	public static final String HDR_CACHE_CONTROL = "cache-control";
	public static final String HDR_CONNECTION = "connection";
	public static final String HDR_CONTENT_DISPOSITION = "content-disposition";
	public static final String HDR_CONTENT_LENGTH = "content-length";
	public static final String HDR_CONTENT_TYPE = "content-type";
	public static final String HDR_HOST = "host";
	public static final String HDR_UPGRADE = "upgrade";
	public static final String HDR_SET_COOKIE = "set-cookie";
	public static final String HDR_COOKIE = "cookie";

	final static Logger LOG = System.getLogger("UHTTPD");

	private final static Selector ALL_SELECTOR = new AllSelector();

	private static final String WEBSOCKET_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	public static HttpBasicAuthentication httpBasicAuthentication(Authenticator<UsernameAndPassword> authenticator) {
		return new HttpBasicAuthentication(authenticator);
	}

	public static ServerBuilder server() {
		return new ServerBuilder();
	}

	public static CookieBuilder cookie(String name, String version) {
		return new CookieBuilder(name, version);
	}

	public static WebSocketBuilder websocket() {
		return new WebSocketBuilder();
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

	private final int backlog;
	private final boolean cache;
	private final Map<Selector, Handler> contentFactories = new LinkedHashMap<>();
	private final Optional<InetAddress> httpAddress;
	private final Optional<Integer> httpPort;
	private final Optional<InetAddress> httpsAddress;
	private final Optional<Integer> httpsPort;
	private final boolean keepAlive;
	private final int keepAliveMax;
	private final int keepAliveTimeoutSecs;
	private final Optional<char[]> keyPassword;
	private final String keyStoreAlias;
	private final Optional<Path> keyStoreFile;

	private final Optional<char[]> keyStorePassword;
	private boolean open = true;
	private Thread otherThread;
	private ExecutorService pool;
	private ServerSocketChannel serversocket;

	private ServerSocketChannel sslServersocket;

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
			serversocket = ServerSocketChannel.open().setOption(StandardSocketOptions.SO_REUSEADDR, true)
					.bind(new InetSocketAddress(httpAddress.orElse(InetAddress.getByName("127.0.0.1")),
							httpPort.orElse(8080)), backlog);
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

//			var ssf = sc.getServerSocketFactory();
//			sslServersocket = (SSLServerSocket) ssf.createServerSocket(httpsPort.get(), backlog,
//					httpsAddress.orElse(InetAddress.getLocalHost()));
//			sslServersocket.setReuseAddress(true);
			throw new UnsupportedOperationException("TODO SSL backed socket channel");
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
				@Override
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

	private KeyStore loadKeyStoreFromJKS(InputStream jksFile, char[] passphrase)
			throws KeyStoreException, NoSuchAlgorithmException, IOException, NoSuchProviderException,
			UnrecoverableKeyException, CertificateException {

		var keystore = KeyStore.getInstance("JKS");
		keystore.load(jksFile, passphrase);
		return keystore;
	}

	private void runOn(ServerSocketChannel so) {
		while (open) {
			LOG.log(Level.DEBUG, "Waiting for connection");
			try {
				pool.execute(new Client(so.accept(), cache, keepAlive, keepAliveTimeoutSecs, keepAliveMax,
						contentFactories, this));
			} catch (Exception e) {
				LOG.log(Level.ERROR, "Failed waiting for connection.", e);
			}
		}
	}
	
	//
	// The following code comes from Apache Http client DateUtils under
	// the same license as this project.
	//

    /**
     * Date format pattern used to parse HTTP date headers in RFC 1123 format.
     */
    public static final String PATTERN_RFC1123 = "EEE, dd MMM yyyy HH:mm:ss zzz";

    /**
     * Date format pattern used to parse HTTP date headers in RFC 1036 format.
     */
    public static final String PATTERN_RFC1036 = "EEE, dd-MMM-yy HH:mm:ss zzz";

    /**
     * Date format pattern used to parse HTTP date headers in ANSI C
     * {@code asctime()} format.
     */
    public static final String PATTERN_ASCTIME = "EEE MMM d HH:mm:ss yyyy";

    private static final String[] DEFAULT_PATTERNS = new String[] {
        PATTERN_RFC1123,
        PATTERN_RFC1036,
        PATTERN_ASCTIME
    };

    private static final Date DEFAULT_TWO_DIGIT_YEAR_START;

    public static final TimeZone GMT = TimeZone.getTimeZone("GMT");

    static {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(GMT);
        calendar.set(2000, Calendar.JANUARY, 1, 0, 0, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        DEFAULT_TWO_DIGIT_YEAR_START = calendar.getTime();
    }

	/**
     * Parses the date value using the given date formats.
     *
     * @param dateValue the date value to parse
     * @param dateFormats the date formats to use
     * @param startDate During parsing, two digit years will be placed in the range
     * {@code startDate} to {@code startDate + 100 years}. This value may
     * be {@code null}. When {@code null} is given as a parameter, year
     * {@code 2000} will be used.
     *
     * @return the parsed date or null if input could not be parsed
     */
    static Date parseDate(
            final String dateValue,
            final String[] dateFormats,
            final Date startDate) {
        final String[] localDateFormats = dateFormats != null ? dateFormats : DEFAULT_PATTERNS;
        final Date localStartDate = startDate != null ? startDate : DEFAULT_TWO_DIGIT_YEAR_START;
        String v = dateValue;
        // trim single quotes around date if present
        // see issue #5279
        if (v.length() > 1 && v.startsWith("'") && v.endsWith("'")) {
            v = v.substring (1, v.length() - 1);
        }

        for (final String dateFormat : localDateFormats) {
            final SimpleDateFormat dateParser = DateFormatHolder.formatFor(dateFormat);
            dateParser.set2DigitYearStart(localStartDate);
            final ParsePosition pos = new ParsePosition(0);
            final Date result = dateParser.parse(v, pos);
            if (pos.getIndex() != 0) {
                return result;
            }
        }
        return null;
    }/**
     * A factory for {@link SimpleDateFormat}s. The instances are stored in a
     * threadlocal way because SimpleDateFormat is not threadsafe as noted in
     * {@link SimpleDateFormat its javadoc}.
     *
     */
    final static class DateFormatHolder {

        private static final ThreadLocal<SoftReference<Map<String, SimpleDateFormat>>>
            THREADLOCAL_FORMATS = new ThreadLocal<SoftReference<Map<String, SimpleDateFormat>>>();

        /**
         * creates a {@link SimpleDateFormat} for the requested format string.
         *
         * @param pattern
         *            a non-{@code null} format String according to
         *            {@link SimpleDateFormat}. The format is not checked against
         *            {@code null} since all paths go through
         *            {@link DateUtils}.
         * @return the requested format. This simple dateformat should not be used
         *         to {@link SimpleDateFormat#applyPattern(String) apply} to a
         *         different pattern.
         */
        public static SimpleDateFormat formatFor(final String pattern) {
            final SoftReference<Map<String, SimpleDateFormat>> ref = THREADLOCAL_FORMATS.get();
            Map<String, SimpleDateFormat> formats = ref == null ? null : ref.get();
            if (formats == null) {
                formats = new HashMap<String, SimpleDateFormat>();
                THREADLOCAL_FORMATS.set(
                        new SoftReference<Map<String, SimpleDateFormat>>(formats));
            }

            SimpleDateFormat format = formats.get(pattern);
            if (format == null) {
                format = new SimpleDateFormat(pattern, Locale.US);
                format.setTimeZone(TimeZone.getTimeZone("GMT"));
                formats.put(pattern, format);
            }

            return format;
        }

        public static void clearThreadLocal() {
            THREADLOCAL_FORMATS.remove();
        }

    }
}