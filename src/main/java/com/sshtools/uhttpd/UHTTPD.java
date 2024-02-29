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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilterInputStream;
import java.io.FilterReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.ref.SoftReference;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ByteChannel;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.text.MessageFormat;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Stack;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * Simple HTTP/HTTPS server, configured using a fluent API.
 *
 * <pre>
 * public class SimpleServer {
 *	   public static void main(String[] args) throws Exception {
 *		   try(var httpd = UHTTPD.server().
 *			   get("/index\\.txt", (tx) -> tx.response("Hello World!")).
 *			   build()); {
 *			   httpd.run();
 *		   }
 *	   }
 * }
 * </pre>
 */
public class UHTTPD {

	/**
	 * Selector that just matches everything. All handlers will be executed.
	 */
	public final static class AllSelector implements HandlerSelector {
		@Override
		public boolean matches(Transaction request) {
			return true;
		}
	}

	/**
	 * Something that provides a way to authenticate a given {@link Credential} and
	 * provide a {@link Principal}.
	 */
	public interface Authenticator<C extends Credential> {
		/**
		 * Authenticate.
		 *
		 * @param credential the gather credentials.
		 * @return principal or empty if authentication failed
		 */
		Optional<Principal> authenticate(C credential);
	}

	/**
	 * Various operations may need a pre-created buffer to be filled. This interface
	 * will be expected.
	 *
	 */
	public interface BufferFiller extends Closeable {
		@Override
		default void close() throws IOException {
		}

		/**
		 * Supply some more data. Upon invocation, the byte buffer will be reset. If
		 * there is content, before exit it should NOT be {@link ByteBuffer#flip()}ped
		 * so that {@link ByteBuffer#position()} is greater than zero.
		 * <p>
		 * If there is no more content, the {@link ByteBuffer#position()} should be
		 * zero. So if you just don't write anything to the buffer this will be the
		 * case.
		 *
		 * @param buffer buffer to fill
		 * @throws IOException on error
		 */
		void supply(ByteBuffer buffer) throws IOException;
	}

	/**
	 * Encapsulates a single HTTP connection. For every {@link SocketChannel} there
	 * will be a single instance of this client. The public API exposes methods to
	 * get at some of the lower level details.
	 * <p>
	 * The details of the HTTP protocol in use (e.g. HTTP 1.1, WebSocket etc) are
	 * delegated to the {@link WireProtocol}. For example
	 * {@link HTTP11WireProtocol}.
	 */
	public static final class Client implements Runnable, Closeable {

		final RootContextImpl rootContext;
		final ByteChannel channel;
		final Scheme scheme;
		final int port;
		final boolean secure;
		final SocketAddress localAddress;
		final SocketAddress remoteAddress;
		final Consumer<Integer> timeoutSetter;

		boolean closed = false;
		int times = 0;
		WireProtocol wireProtocol;
		Charset charset = Charset.defaultCharset();

		Client(boolean secure, int port, Scheme scheme, SocketChannel socket, RootContextImpl rootContext) throws IOException {
			this.port = port;
			this.secure = secure;
			this.scheme = scheme;
			this.channel = socket;
			this.rootContext = rootContext;
			this.rootContext.clients.add(this);
			this.localAddress = socket.getLocalAddress();
			this.remoteAddress = socket.getRemoteAddress();

			wireProtocol = new HTTP11WireProtocol(this);
			timeoutSetter = new Consumer<Integer>() {
				@Override
				public void accept(Integer t) {
					try {
						socket.socket().setSoTimeout(t);
					} catch (SocketException e) {
						throw new UncheckedIOException(e);
					}
				}
			};
		}
		
		Client(boolean secure, int port, Scheme scheme, Socket socket, RootContextImpl rootContext) throws IOException {
			this.port = port;
			this.secure = secure;
			this.scheme = scheme;
			this.localAddress = socket.getLocalSocketAddress();
			this.remoteAddress = socket.getRemoteSocketAddress();
			
			var in = Channels.newChannel(socket.getInputStream());
			var out = Channels.newChannel(socket.getOutputStream());
			this.channel = new ByteChannel() {
				
				@Override
				public int write(ByteBuffer src) throws IOException {
					return out.write(src);
				}
				
				@Override
				public boolean isOpen() {
					return in.isOpen() && out.isOpen();
				}
				
				@Override
				public void close() throws IOException {
					try {
						in.close();
					}
					finally {
						out.close();
					}	
				}
				
				@Override
				public int read(ByteBuffer dst) throws IOException {
					return in.read(dst);
				}
			};
			this.rootContext = rootContext;
			this.rootContext.clients.add(this);

			wireProtocol = new HTTP11WireProtocol(this);
			timeoutSetter = new Consumer<Integer>() {
				@Override
				public void accept(Integer t) {
					try {
						socket.setSoTimeout(t);
					} catch (SocketException e) {
						throw new UncheckedIOException(e);
					}
				}
			};
		}

		/**
		 * Get the active character set.
		 *
		 * @return character set
		 */
		public final Charset charset() {
			return charset;
		}

		/**
		 * Not public API
		 */
		@Override
		public final void close() throws IOException {
			if (!closed) {
				closed = true;
				try {
					channel.close();
				} catch (IOException ioe) {
				}
				rootContext.clients.remove(this);
			}
		}

		/**
		 * Not public API
		 */
		@Override
		public final void run() {
			try {
				var client = localAddress();
				if (client == null) {
					LOG.log(Level.ERROR, "Socket was lost between accepting it and starting to handle it. "
							+ "This can be caused by the system socket factory being swapped out for another "
							+ "while the boot HTTP server is running. Closing down the server now, it has become useless!");
					rootContext.close();
				} else {
					try {
						LOG.log(Level.DEBUG, "{0} connected to server", remoteAddress());
						do {
							wireProtocol.transact();
							times++;
						} while (!closed && times < rootContext.keepAliveMax);
					} catch (ClosedChannelException | EOFException e) {
						LOG.log(Level.TRACE, "EOF.", e);
					} catch(SocketTimeoutException ste) {
						LOG.log(Level.TRACE, "Timeout.", ste);
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

		/**
		 * Get the scheme this connection is using.
		 *
		 * @return scheme
		 */
		public final Scheme scheme() {
			return scheme;
		}

		/**
		 * Get the underlying protocol currently active. This may change as the
		 * connection is upgraded to a WebSocket.
		 *
		 * @return current wire protocol
		 */
		public final WireProtocol wireProtocol() {
			return wireProtocol;
		}

		/**
		 * Get the local address this client is connected to, most likely an {@link InetSocketAdddress}.
		 *
		 * @return local address
		 */
		public final SocketAddress localAddress() {
			return localAddress;
		}

		/**
		 * Get the remote address this client is connected to, most likely an {@link InetSocketAdddress}.
		 *
		 * @return local address
		 */
		public final SocketAddress remoteAddress() {
			return remoteAddress;
		}

		final ByteChannel channel() {
			return channel;
		}

		/**
		 * Get the local port this client is connected to. If this is not a TCP connection, zero
		 * will be returned.
		 *  
		 * @return port
		 */
		public final int port() {
			try {
				var addr = localAddress();
				if (addr instanceof InetSocketAddress) {
					return ((InetSocketAddress) addr).getPort();
				}
			} catch (Exception e) {
				LOG.log(Level.TRACE, "Failed to get socket address.", e);
			}
			return port;
		}

		public final boolean secure() {
			return secure;
		}

		void timeout(int ms) {
			timeoutSetter.accept(ms);
		}

	}

	/**
	 * Selector that executes a {@link Handler} if all {@link HandlerSelector}s it
	 * contains match.
	 *
	 */
	public static final class CompoundSelector implements HandlerSelector {
		private HandlerSelector[] selectors;

		CompoundSelector(HandlerSelector... selectors) {
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
	 * Represents the content sent from the client, e.g. a form submission. Content
	 * is made up of multiple {@link Part}s.
	 */
	public interface Content extends Closeable {
		/**
		 * Get the entire content as a channel.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream,
		 * parts or name parts.
		 *
		 * @return as stream
		 */
		ReadableByteChannel asChannel();

		/**
		 * A convenience method to get a part that is a piece of {@link FormData} given
		 * it's name, throwing an exception if there is no such part.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream,
		 * channel or parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default FormData asFormData(String name) {
			return ofFormData(name).orElseThrow();
		}

		/**
		 * A convenience method to get a part that is a {@link Named} given it's name,
		 * throwing an exception if there is no such part.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream,
		 * channel or parts.
		 *
		 * @param name name
		 * @return named.
		 */
		default Named asNamed(String name) {
			return ofNamed(name).orElseThrow();
		}

		/**
		 * Get all of the {@link Part}s that make up this content.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream,
		 * channel or a named part.
		 *
		 * @return parts
		 */
		default Iterable<Part> asParts() {
			return asParts(Part.class);
		}

		/**
		 * Get all of the {@link Part}s of a certain type that make up this content.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream,
		 * channel or a named part.
		 *
		 * @param partType type
		 * @return parts
		 */
		<P extends Part> Iterable<P> asParts(Class<P> partType);

		/**
		 * Get the entire content as a stream.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a channel,
		 * parts or name parts.
		 *
		 * @return as stream
		 */
		InputStream asStream();

		/**
		 * Get the overall content type (i.e. <code>Content-Type</strong> header) of
		 * this content. Individual parts will have different content types.
		 *
		 * @return content type
		 */
		Optional<String> contentType();

		/**
		 * A convenience method to get if a part that is a piece of {@link FormData} exists.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream or
		 * parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default boolean hasFormData(String name) {
			return ofFormData(name).isPresent();
		}

		/**
		 * A convenience method to get a part that is a piece of {@link FormData} given
		 * it's name.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream or
		 * parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default Optional<FormData> ofFormData(String name) {
			return ofPart(name, FormData.class);
		}

		/**
		 * A convenience method to get a part that is a {@link Named} given it's name.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream or
		 * parts.
		 *
		 * @param name name
		 * @return form data.
		 */
		default Optional<Named> ofNamed(String name) {
			return ofPart(name, Named.class);
		}

		/**
		 * A convenience method to get if a part exists.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream or
		 * parts.
		 *
		 * @param name name
		 * @param clazz type of part
		 * @return form data.
		 */
		default <P extends Part> boolean hasPart(String name, Class<P> clazz) {
			return ofPart(name, clazz).isPresent();
		}

		/**
		 * Get a part given it's name and class.
		 * <p>
		 * This cannot be used if the content has already been retrieved as a stream or
		 * parts.
		 *
		 * @param <P>   type of part
		 * @param name  part name
		 * @param clazz class of part
		 * @return part
		 */
		<P extends Part> Optional<P> ofPart(String name, Class<P> clazz);

		/**
		 * Get the size of this content if known.
		 *
		 * @return size
		 */
		Optional<Long> size();
	}

	public interface Group extends Closeable, Handler {
		
		@Override
		void close();
	}

	public interface Context extends Group {

		String generateETag(Path resource);

		Path tmpDir();
	}

	public final static class ContextBuilder extends AbstractWebContextBuilder<ContextBuilder, Context> {

		private final String pathExpression;

		ContextBuilder(String pathExpression) {
			this.pathExpression = pathExpression;
		}

		@Override
		public Context build() throws UnknownHostException, IOException {
			return new ContextImpl(this);
		}
	}

	public interface Cookie {
		/**
		 * Domain of this cookie
		 *
		 * @return domain of this cookie
		 */
		Optional<String> domain();

		/**
		 * Explicit date and time when this cookie expires.
		 *
		 * @return cookie expires
		 */
		Optional<Instant> expires();

		/**
		 * HTTP usage only.
		 */
		boolean httpOnly();

		/**
		 * The maximum age of this cook in seconds.
		 *
		 * @return the maximum age of this cookie
		 */
		Optional<Long> maxAge();

		/**
		 * Returns the name of this cookie.
		 *
		 * @return The name of this cookie
		 */
		String name();

		/**
		 * Path of this cookie
		 *
		 * @return path of this cookie
		 */
		Optional<String> path();

		/**
		 * Returns the value of "SameSite" for this cookie
		 *
		 * @return same site of this cookie
		 */
		Optional<SameSite> sameSite();

		/**
		 * Get if this cookie is secure.
		 *
		 * @return secure cookie
		 */
		boolean secure();

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

	}

	/**
	 * Use to build {@link Cookie} instances for setting on responses.
	 */

	public final static class CookieBuilder {
		
		private static final Calendar effectivelyNever;
		
		static {
			effectivelyNever = Calendar.getInstance();
			effectivelyNever.set(Calendar.YEAR, 3999);
			effectivelyNever.set(Calendar.MONTH, 12);
			effectivelyNever.set(Calendar.DAY_OF_MONTH, 31);
			effectivelyNever.set(Calendar.HOUR_OF_DAY, 23);
			effectivelyNever.set(Calendar.MINUTE, 59);
			effectivelyNever.set(Calendar.SECOND, 59);
			effectivelyNever.set(Calendar.MILLISECOND, 0);
		}

		String name;
		CookieVersion version = CookieVersion.V1;
		Optional<Boolean> secure = Optional.empty();
		boolean httpOnly;
		String value;
		Optional<String> path = Optional.empty();
		Optional<String> domain = Optional.empty();
		Optional<Long> maxAge = Optional.empty();
		Optional<Instant> expires = Optional.empty();
		Optional<SameSite> sameSite = Optional.empty();
		
		public CookieBuilder withName(String name) {
			this.name = name;
			return this;
		}
		
		public CookieBuilder withValue(String value) {
			this.value = value;
			return this;
		}
		
		public Cookie build() {
			final var secure = this.secure.orElseGet(() -> Transaction.get().secure());
			final var domain = this.domain;
			final var expires = this.expires;
			final var httpOnly = this.httpOnly;
			final var maxAge = this.maxAge;
			final var name = this.name;
			final var path = this.path;
			final var sameSite = this.sameSite;
			final var value = this.value;
			final var version = this.version;
			return new Cookie() {

				@Override
				public Optional<String> domain() {
					return domain;
				}

				@Override
				public Optional<Instant> expires() {
					return expires;
				}

				@Override
				public boolean httpOnly() {
					return httpOnly;
				}

				@Override
				public Optional<Long> maxAge() {
					return maxAge;
				}

				@Override
				public String name() {
					return name;
				}

				@Override
				public Optional<String> path() {
					return path;
				}

				@Override
				public Optional<SameSite> sameSite() {
					return sameSite;
				}

				@Override
				public boolean secure() {
					return secure;
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
						var date = new Date(p.toEpochMilli());
						b.append(formatDate(date));
					});
					if (secure) {
						b.append("; Secure");
					}
					if (httpOnly) {
						b.append("; HttpOnly");
					}
					sameSite.ifPresent(p -> {
						b.append("; SameSite=");
						b.append(Character.toUpperCase(p.name().charAt(0)) + p.name().substring(1).toLowerCase());
					});

					return b.toString();
				}

				@Override
				public String value() {
					return value;
				}

				@Override
				public CookieVersion version() {
					return version;
				}
			};
		}

		public CookieBuilder withDomain(String domain) {
			this.domain = Optional.of(domain);
			return this;
		}

		public CookieBuilder withExpires(Date expires) {
			this.expires = Optional.of(expires.toInstant());
			return this;
		}

		public CookieBuilder withExpires(Instant instant) {
			this.expires = Optional.of(instant);
			return this;
		}

		public CookieBuilder withHttpOnly() {
			this.httpOnly = true;
			return this;
		}

		public CookieBuilder withMaxAge(long maxAge) {
			this.maxAge = Optional.of(maxAge);
			return this;
		}

		public CookieBuilder withPath(String path) {
			this.path = Optional.of(path);
			return this;
		}

		public CookieBuilder withSameSite(SameSite sameSite) {
			this.sameSite = Optional.of(sameSite);
			return this;
		}

		public CookieBuilder withSecure() {
			return withSecure(true);
		}

		public CookieBuilder withSecure(boolean secure) {
			this.secure = Optional.of(secure);
			return this;
		}

		public CookieBuilder withVersion(CookieVersion version) {
			this.version = version;
			return this;
		}

		public CookieBuilder withMaxExpiry() {
			
			return withExpires(effectivelyNever.getTime());
		}

	}

	/**
	 * Version of @{link {@link Cookie}.
	 */
	public enum CookieVersion {
		V1, V2
	}

	/**
	 * Represents some piece of information that can be used to authenticate a user.
	 */
	public interface Credential {
		/**
		 * Turn this {@link Credential} into a {@link Principal} if success its
		 * <code>true</code>, otherwise return an empty {@link Optional}.
		 *
		 * @param success whether authentication was successful or not
		 * @return a principal or empty
		 */
		Optional<Principal> result(boolean success);
	}

	/**
	 * A {@link Part} that represents a piece form data, as sent with a content type
	 * of <code>multipart/form-data</code>
	 */
	public final static class FormData implements TextPart {

		private final Optional<String> contentType;
		private final Optional<String> filename;
		private final String name;
		private final MultipartBoundaryStream content;
		private final Charset charset;
		private Path storedContent;
		private FilterInputStream filter;

		FormData(String contentType, Charset charset, String contentDisposition, MultipartBoundaryStream content) {
			Map<String, Named> map = contentDisposition == null ? Collections.emptyMap()
					: Named.parseSeparatedStrings(contentDisposition);
			this.name = map.get("name").asString();
			this.charset = charset;
			this.content = content;
			this.contentType = Optional.ofNullable(contentType);
			this.filename = Optional.ofNullable(map.get("filename")).map(n -> n.asString());
		}

		@Override
		public final ReadableByteChannel asChannel() {
			return Channels.newChannel(asStream());
		}

		@Override
		public final Reader asReader() {
			return new InputStreamReader(asStream(), charset());
		}

		@Override
		public InputStream asStream() {
			if (storedContent == null) {
				if (filter == null) {
					try {
						storedContent = Files.createTempFile("uhttpd", ".part");
						var out = Files.newOutputStream(storedContent);
						return filter = new FilterInputStream(content) {
							@Override
							public void close() throws IOException {
								try {
									super.close();
								} finally {
									out.close();
								}
							}

							@Override
							public int read() throws IOException {
								var r = super.read();
								if (r != -1) {
									out.write(r);
								}
								return r;
							}

							@Override
							public int read(byte[] b, int off, int len) throws IOException {
								var r = super.read(b, off, len);
								if (r != -1) {
									out.write(b, off, r);
								}
								return r;
							}
						};
					} catch (IOException ioe) {
						throw new UncheckedIOException(ioe);
					}
				} else {
					return filter;
				}
			} else {
				try {
					return Files.newInputStream(storedContent);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			}
		}

		public final Charset charset() {
			return charset;
		}

		@Override
		public void close() {
			if (storedContent != null) {
				try {
					Files.delete(storedContent);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				} finally {
					storedContent = null;
				}
			}
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
		 * Get the filename of this part, if the part is a file upload.
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
		public boolean satisfied() {
			return content == null || content.state == com.sshtools.uhttpd.UHTTPD.MultipartBoundaryStream.State.END;
		}

		@Override
		public void satisfy() throws IOException {
			TextPart.super.satisfy();
			asStream().transferTo(OutputStream.nullOutputStream());
		}

		@Override
		public Optional<String> ofString() {
			try (var stream = asStream()) {
				return Optional.of(new String(stream.readAllBytes(), charset));
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}
	}

	/**
	 * Interface to be implemented to handle any request received by the server.
	 * {@link Handler} is fundamental to UHTTPD.
	 */
	public interface Handler {
		void get(Transaction req) throws Exception;
		
		default void handleMultiple(Transaction tx, Handler... handlers) throws Exception {
			handleMultiple(tx, Arrays.asList(handlers));
		}
		
		default void handleMultiple(Transaction tx, Collection<? extends Handler> handlers) throws Exception {
			for (var c : handlers) {
				c.get(tx);
	
				if (tx.responded() || tx.hasResponse())
					break;
			}
		}
	}

	/**
	 * A selector decides if a {@link Handler} applies to a given
	 * {@link Transaction}, e.g. should a handler handle a GET request for a certain
	 * URI.
	 */
	public interface HandlerSelector {
		boolean matches(Transaction request);
	}
	
	/**
	 * A simple session.
	 * 
	 * @see #sessionCookies()
	 */
	public static class Session {
		
		private static ThreadLocal<Session> current = new ThreadLocal<>();
		
		private final String id;
		private final boolean attached;
		
		Session() {
			id = UUID.randomUUID().toString();
			this.attached = false;
		}
		
		Session(String id) {
			this.id = id;
			this.attached = true;
		}

		public static Session get() {
			return get(true).orElseThrow();
		}

		public static Optional<Session> get(boolean create) {
			var session = current.get();
			if(session == null && create) {
				session = new Session();
				current.set(session);
				var tx = Transaction.get();
				if(tx.responded()) {
					throw new IllegalStateException("A session cookie must be created, but the response has already been committed.");
				}
			}
			return Optional.ofNullable(session);
		}
		
		@Override
		public int hashCode() {
			return Objects.hash(id);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Session other = (Session) obj;
			return Objects.equals(id, other.id);
		}

		public final String id() {
			return id;
		}
		
		public final boolean attached() {
			return attached;
		}
	}

	/**
	 * Builds a {@link Handler} that adds session tracking support using a cookie.
	 */
	public final static class SessionCookiesBuilder {

		private Optional<String> cookieName = Optional.empty();
		private Optional<Function<Transaction, CookieBuilder>> cookieBuilder = Optional.empty();

		SessionCookiesBuilder() {
		}
		
		/**
		 * Set the cookie name to use.
		 * 
		 * @param name cookie name
		 * @return this for chaining
		 */
		public SessionCookiesBuilder withCookieName(String name) {
			this.cookieName = Optional.of(name);
			return this;
		}
		
		/**
		 * Use a custom {@link CookieBuilder} to create the session cookie. The default will
		 * create simple, secure session cookies.
		 * 
		 * @param name cookie name
		 * @return this for chaining
		 */
		public SessionCookiesBuilder withCookieBuilder(Function<Transaction, CookieBuilder> cookieBuilder) {
			this.cookieBuilder = Optional.of(cookieBuilder);
			return this;
		}

		/**
		 * Builds the handler.
		 *
		 * @return handler
		 * @throws UnknownHostException
		 * @throws IOException
		 */
		public Handler build() throws UnknownHostException, IOException {
			var cookieName = this.cookieName.orElse(DEFAULT_SESSION_COOKIE_NAME);
			var cookieBuilder = this.cookieBuilder;
			return new Handler() {
				@Override
				public void get(Transaction tx) throws Exception {
					var cookieOr = tx.cookieOr(cookieName);
					cookieOr.ifPresent(c -> Session.current.set(new Session(c.value())));
					
					/* TODO: this is not ideal. We should only really add the cookie
					 *       if the Session was actually accessed and not invalidated
					 *       before responding
					 *       
					 * TODO remove cookie if invalidated
					 */
					addCookie(cookieName, cookieBuilder, tx, Session.get());
					
//					try {
//						for(var handler : handlers) {
//							handler.get(tx);
//							var session = Session.current.get(); 
//							if(session != null && !session.attached()) {
//								if(tx.responded())
//									throw new IllegalStateException("Cannot attach session cookie, already responsed.");
//								addCookie(cookieName, cookieBuilder, tx, session);
//							}
//							if (tx.responded())
//								break;
//						}
//					}
//					finally {
//						Session.current.remove();
//					}
				}

				private void addCookie(String cookieName,
						Optional<Function<Transaction, CookieBuilder>> cookieBuilder, Transaction tx, Session session) {
					tx.cookie((cookieBuilder.map(f -> f.apply(tx)).orElseGet(() -> new CookieBuilder())).withName(cookieName).withValue(session.id()).build());
				}
			};
		}

	}

	/**
	 * Builds a {@link Handler} to support HTTP Basic Authentication. See
	 * {@link UHTTPD#httpBasicAuthentication(Authenticator)}.
	 */
	public final static class HttpBasicAuthenticationBuilder {

		private Authenticator<UsernameAndPassword> authenticator;
		private Optional<String> realm = Optional.empty();

		HttpBasicAuthenticationBuilder(Authenticator<UsernameAndPassword> authenticator) {
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
		public HttpBasicAuthenticationBuilder withRealm(String realm) {
			this.realm = Optional.of(realm);
			return this;
		}
	}

	/**
	 * Constants for HTTP methods.
	 */
	public enum Method {
		CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE, COPY, LOCK, MKCOL, MOVE, PROPFIND, PROPPATCH,
		UNLOCK
	}

	/**
	 * Select a handler based on its {@link Transaction#method()}. If the method
	 * matches, the handler will be executed.
	 *
	 */
	public static final class MethodSelector implements HandlerSelector {

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

			var namedMap = new LinkedHashMap<String, Named>();
			map.forEach((k, v) -> {
				namedMap.put(k, new Named(k, v));
			});
			return namedMap;
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
			return new Named(name, hasValue() ? Arrays.asList(asString().split(separator)).stream().map(s -> s.trim())
					.collect(Collectors.toList()) : Collections.emptyList());
		}

		@Override
		public String name() {
			return name;
		}

		@Override
		public boolean satisfied() {
			return true;
		}

		@Override
		public String toString() {
			return "Named [name=" + name + ", values=" + values + "]";
		}

		@Override
		public Optional<String> ofString() {
			return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
		}

		public List<String> values() {
			return Collections.unmodifiableList(values);
		}
	}
	
	public final static class NCSALoggerBuilder {
		private Path directory = Paths.get(System.getProperty("user.dir"));
		private String filenamePattern = "access_log_%d.log";
		private String filenameDateFormat = "ddMM";
		private boolean serverName;
		private boolean extended = true;
		private boolean append = true;
		
		public NCSALoggerBuilder withServerName(boolean serverName) {
			this.serverName = serverName;
			return this;
		}
		
		public NCSALoggerBuilder withAppend(boolean append) {
			this.append = append;
			return this;
		}
		public NCSALoggerBuilder withExtended(boolean extended) {
			this.extended = extended;
			return this;
		}
		
		public NCSALoggerBuilder withDirectory(Path directory) {
			this.directory = directory;
			return this;
		}
		
		public NCSALoggerBuilder withFilenamePattern(String filenamePattern) {
			this.filenamePattern = filenamePattern;
			return this;
		}
		
		public NCSALoggerBuilder withFilenameDateFormat(String filenameDateFormat) {
			this.filenameDateFormat = filenameDateFormat;
			return this;
		}
		
		public Consumer<Transaction> build() {
			return new NCSALogger(this);
		}
		
		private final static class NCSALogger implements Consumer<Transaction> {
			
			private PrintWriter writer;
			private final Path dir;
			private final SimpleDateFormat formatter;
			private final boolean serverName;
			private final boolean extended;
			private final boolean append;
			private final String filenamePattern;
			
			private Path logFile;
			private Object lock = new Object();

			private NCSALogger(NCSALoggerBuilder bldr) {
				this.dir = bldr.directory;
				this.append = bldr.append;
				this.formatter = new SimpleDateFormat(bldr.filenameDateFormat);
				this.serverName = bldr.serverName;
				this.extended = bldr.extended;
				this.filenamePattern = bldr.filenamePattern;
				
				try {
					Files.createDirectories(dir);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			}

			@Override
			public void accept(Transaction tx) {
				var date = new Date();
				
				synchronized(lock) {
					var filename =  filenamePattern.replace("%d", formatter.format(date));				
					if(logFile == null || !filename.equals(logFile.getFileName().toString())) {
						if(writer != null)
							writer.close();
						logFile = dir.resolve(filename);
						try {
							writer = new PrintWriter(Files.newBufferedWriter(logFile, openOpens()), true);
						} catch (IOException e) {
							throw new UncheckedIOException(e);
						}
					}
				}
				
				var buf= new StringBuilder(256);
	            if (serverName) {
	                buf.append(tx.host());
	                buf.append(' ');
	            }

	            buf.append(tx.remoteAddress());
	            buf.append(" - ");
	            tx.principal().ifPresentOrElse(p -> buf.append(p.getName()), () -> buf.append(" - "));

	            buf.append(" [");
                buf.append(new Date(tx.timestamp().toEpochMilli()).toString());

	            buf.append("] \"");
	            buf.append(tx.method().toString());
	            buf.append(' ');
	            buf.append(tx.uri());
	            buf.append(' ');
	            buf.append(tx.secure() ? "HTTPS" : "HTTP");
	            buf.append("\" ");
                int status = tx.responseCode().map(s -> s.getCode()).orElse(0);
                if (status <= 0)
                    status = 404;
                buf.append((char)('0' + ((status / 100) % 10)));
                buf.append((char)('0' + ((status / 10) % 10)));
                buf.append((char)('0' + (status % 10)));

	            var responseLength = tx.responseLength().orElse(-1l);
	            if (responseLength >= 0)
	            {
	                buf.append(' ');
	                if (responseLength > 99999)
	                    buf.append(responseLength);
	                else
	                {
	                    if (responseLength > 9999)
	                        buf.append((char)('0' + ((responseLength / 10000) % 10)));
	                    if (responseLength > 999)
	                        buf.append((char)('0' + ((responseLength / 1000) % 10)));
	                    if (responseLength > 99)
	                        buf.append((char)('0' + ((responseLength / 100) % 10)));
	                    if (responseLength > 9)
	                        buf.append((char)('0' + ((responseLength / 10) % 10)));
	                    buf.append((char)('0' + (responseLength) % 10));
	                }
	                buf.append(' ');
	            }
	            else
	                buf.append(" - ");

	            if(extended) {
	                tx.headerOr(HDR_REFERER).ifPresentOrElse(v -> {
	                	buf.append('"');
			            buf.append(v);
			            buf.append("\" ");
	                }, () -> buf.append("\"-\" "));
	                
	
	                tx.headerOr(HDR_USER_AGENT).ifPresentOrElse(v -> {
	                	buf.append('"');
			            buf.append(v);
			            buf.append("\" ");
	                }, () -> buf.append("\"-\" "));
	            }
		
                var now = System.currentTimeMillis();
                buf.append(' ');
                buf.append(now - tx.timestamp().toEpochMilli());
                
				synchronized(lock) {
					writer.println(buf.toString());
				}
			}

			private OpenOption[] openOpens() {
				if(append)
					return new OpenOption[] { StandardOpenOption.WRITE, StandardOpenOption.APPEND, StandardOpenOption.CREATE };
				else
					return new OpenOption[] { StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING };
			}
			
		}
	}

	public interface OnWebSocketClose {
		void closed(int code, String reason, WebSocket websocket);
	}

	public interface OnWebSocketData {
		void receive(ByteBuffer data, boolean finalFragment, WebSocket websocket);
	}

	public interface OnWebSocketHandshake {
		String handshake(Transaction tx, String... protocols);
	}

	public interface OnWebSocketOpen {
		void open(WebSocket websocket);
	}

	public interface OnWebSocketText {
		void receive(String text, WebSocket websocket);
	}

	public interface Part extends Closeable {
		ReadableByteChannel asChannel();

		Reader asReader();

		InputStream asStream();

		String asString();

		@Override
		default void close() {
		}

		String name();

		boolean satisfied();

		default void satisfy() throws IOException {
			if (satisfied())
				throw new IllegalStateException("Already satisfied.");
		}
	}

	public enum Protocol {
		HTTP_0, HTTP_1_0, HTTP_1_1, HTTP_2, HTTP_3;

		String text() {
			return "HTTP/" + (name().substring(5).replace('_', '.'));
		}
	}

	/**
	 * Select a {@link Handler} based on its {@link Transaction#path()}, i.e. URI.
	 * If the URI matches, the handler will be executed.
	 *
	 */
	public static final class RegularExpressionSelector implements HandlerSelector {

		private Pattern pattern;

		public RegularExpressionSelector(String regexp) {
			pattern = Pattern.compile(regexp);
		}

		@Override
		public boolean matches(Transaction req) {
			var path = req.path().toString();
			var matcher = pattern.matcher(path);
			if(matcher.matches()) {
				for(int i = 1 ; i <= matcher.groupCount(); i++) {
					req.matches.add(matcher.group(i));
				}
			}
			return matcher.matches();
		}
	}

	public interface RootContext extends Context, Runnable {

		void join() throws InterruptedException;

		void start();

		Optional<Integer> httpsPort();

		Optional<Integer> httpPort();
	}

	/**
	 * Builder to create a new instance of the main server, an {@link UHTTPD}
	 * instance.
	 */
	public final static class RootContextBuilder extends AbstractWebContextBuilder<RootContextBuilder, RootContext> {
		private int backlog = 10;
		private boolean cache = true;
		private boolean daemon;
		private Optional<InetAddress> httpAddress = Optional.empty();
		private Optional<Integer> httpPort = Optional.of(8080);
		private Optional<InetAddress> httpsAddress = Optional.empty();
		private Optional<Integer> httpsPort = Optional.empty();
		private boolean keepAlive = true;
		private boolean gzip = true;
		private int keepAliveMax = 100;
		private int keepAliveTimeoutSecs = 15;
		private Optional<char[]> keyPassword = Optional.empty();
		private Optional<Path> keyStoreFile = Optional.empty();
		private Optional<String> keyStoreType = Optional.empty();
		private Optional<char[]> keyStorePassword = Optional.empty();
		private String threadName = "UHTTPD";
		private Optional<Runner> runner = Optional.empty();
		private Optional<Long> gzipMinSize = Optional.empty();
		private int sendBufferSize = DEFAULT_BUFFER_SIZE;
		private int recvBufferSize = DEFAULT_BUFFER_SIZE;
		private Optional<KeyStore> keyStore = Optional.empty();
		private int maxUnchunkedSize = 1024 * 512;
		
		private RootContextBuilder() {
			statusHandlers.put(Status.INTERNAL_SERVER_ERROR, (tx) -> {
				tx.response("text/html",
						"<html><body><h1>Internal Server Error</h1><p>__msg__</p><br/><pre>__trace__</pre></body></html>"
								.replace("__msg__", tx.error().map(e -> e.getMessage()).orElse("No message supplied."))
								.replace("__trace__", tx.errorTrace().orElse("")));
			});
		}

		public RootContextBuilder asDaemon() {
			daemon = true;
			return this;
		}

		@Override
		public RootContext build() throws IOException {
			return new RootContextImpl(this);
		}

		public RootContextBuilder withBacklog(int backlog) {
			this.backlog = backlog;
			return this;
		}

		public RootContextBuilder withHttp(int httpPort) {
			this.httpPort = Optional.of(httpPort);
			return this;
		}

		public RootContextBuilder withHttpAddress(InetAddress httpAddress) {
			this.httpAddress = Optional.of(httpAddress);
			return this;
		}

		public RootContextBuilder withHttpAddress(String httpAddress) {
			try {
				this.httpAddress = Optional.of(InetAddress.getByName(httpAddress));
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid address.", e);
			}
			return this;
		}

		public RootContextBuilder withHttps() {
			return withHttps(8443);
		}

		public RootContextBuilder withHttps(int httpsPort) {
			this.httpsPort = Optional.of(httpsPort);
			return this;
		}

		public RootContextBuilder withHttpsAddress(InetAddress httpsAddress) {
			this.httpsAddress = Optional.of(httpsAddress);
			return this;
		}

		public RootContextBuilder withHttpsAddress(String httpsAddress) {
			try {
				this.httpsAddress = Optional.of(InetAddress.getByName(httpsAddress));
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid address.", e);
			}
			return this;
		}

		public RootContextBuilder withKeepaliveMax(int keepAliveMax) {
			this.keepAliveMax = keepAliveMax;
			return this;
		}

		public RootContextBuilder withKeepaliveTimeoutSecs(int keepAliveTimeoutSecs) {
			this.keepAliveTimeoutSecs = keepAliveTimeoutSecs;
			return this;
		}

		public RootContextBuilder withKeyPassword(char[] keyPassword) {
			this.keyPassword = Optional.of(keyPassword);
			return this;
		}

		public RootContextBuilder withKeyStore(KeyStore keyStore) {
			this.keyStore = Optional.of(keyStore);
			return this;
		}

		public RootContextBuilder withKeyStoreFile(Path keyStoreFile) {
			this.keyStoreFile = Optional.of(keyStoreFile);
			return this;
		}

		public RootContextBuilder withKeyStorePassword(char[] keyStorePassword) {
			this.keyStorePassword = Optional.of(keyStorePassword);
			return this;
		}

		public RootContextBuilder withKeyStoreType(String keyStoreType) {
			this.keyStoreType = Optional.of(keyStoreType);
			return this;
		}

		public RootContextBuilder withMaxUnchunkedSize(int maxUnchunkedSize) {
			this.maxUnchunkedSize = maxUnchunkedSize;
			return this;
		}

		public RootContextBuilder withMinCompressableSize(long gzipMinSize) {
			this.gzipMinSize = Optional.of(gzipMinSize);
			return this;
		}

		public RootContextBuilder withoutCache() {
			this.cache = false;
			return this;
		}

		public RootContextBuilder withoutCompression() {
			this.gzip = false;
			return this;
		}

		public RootContextBuilder withoutHttp() {
			this.httpPort = Optional.empty();
			return this;
		}

		public RootContextBuilder withoutHttps() {
			this.httpsPort = Optional.empty();
			return this;
		}

		public RootContextBuilder withoutKeepalive() {
			this.keepAlive = false;
			return this;
		}

		public RootContextBuilder withRunner(Runner runner) {
			this.runner = Optional.of(runner);
			return this;
		}

		public RootContextBuilder withSendBufferSize(int sendBufferSize) {
			this.sendBufferSize = sendBufferSize;
			return this;
		}

		public RootContextBuilder withRecvBufferSize(int recvBufferSize) {
			this.recvBufferSize = recvBufferSize;
			return this;
		}

		public RootContextBuilder withThreadName(String threadName) {
			this.threadName = threadName;
			return this;
		}
	}

	/**
	 * The {@link Runner} interface provides access to the scheduler. Every HTTP
	 * connection access to at least one thread (a second thread may be required for
	 * tunnelling). This action has been abstracted to allow plugging in Fibres from
	 * project Loom when it is generally availabel.
	 *
	 */
	public interface Runner extends Closeable {

		@Override
		default void close() {
		}

		/**
		 * Run a task.
		 *
		 * @param runnable task
		 * @throws Exception
		 */
		void run(Runnable runnable);
	}

	/**
	 * The "Same Site" attribute used by {@link Cookie} to mitigate CSRF attacks.
	 * Currently a draft.
	 * https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-07
	 */
	public enum SameSite {
		STRICT, LAX, NONE;
	}

	public enum Scheme {
		HTTP, HTTPS
	}

	public enum Status {
		CONTINUE(100, "Continue"), SWITCHING_PROTOCOLS(101, "Switching Protocols"), PROCESSING(102, "Processing"),
		OK(200, "OK"), CREATED(201, "Created"), ACCEPTED(202, "Accepted"),
		NON_AUTHORITATIVE_INFORMATION(203, "Non-Authoritative Information"), NO_CONTENT(204, "No Content"),
		RESET_CONTENT(205, "Reset Content"), PARTIAL_CONTENT(206, "Reset Content"), MULTI_STATUS(207, "Multi-Status"),
		MOVED_PERMANENTLY(301, "Moved Permanently"), MOVED_TEMPORARILY(302, "Moved Temporarily"),
		SEE_OTHER(303, "See Other"), NOT_MODIFIED(304, "Not Modified"), USE_PROXY(305, "Use Proxy"),
		BAD_REQUEST(400, "Bad Request"), UNAUTHORIZED(401, "Unauthorized"), PAYMENT_REQUIRED(402, "Payment Required"),
		FORBIDDEN(403, "Forbidden"), NOT_FOUND(404, "Not Found"), METHOD_NOT_ALLOWED(405, "Method Not Allowed"),
		NOT_ACCEPTABLE(406, "Not Acceptable"), PROXY_AUTHENTICATION_REQUIRED(407, "Proxy Authentication Required"),
		REQUEST_TIMEOUT(408, "Request Timeout"), CONFLICT(409, "Conflict"), GONE(410, "Gone"),
		LEBNGTH_REQUIRED(411, "Length Required"), PRECONDITION_FAILED(412, "Precondition Failed"),
		REQUEST_ENTITY_TOO_LARGE(413, "Request Entity Too Large"), REQUEST_URI_TOO_LONG(414, "Request-URI Too Long"),
		UNSUPPORTED_MEDIA_TYPE(415, "Request-URI Too Long"), UNPROCESSABLE_ENTITY(422, "Unprocessable Entity"),
		LOCKED(423, "Locked"), FAILED_DEPENDENCY(424, "Failed Dependency"), UPGRADE_REQUIRED(426, "Failed Dependency"), INTERNAL_SERVER_ERROR(500, "Not Found"),
		NOT_IMPLEMENTED(501, "Not Implemented"), BAD_GATEWAY(502, "Bad Gateway"),
		SERVICE_UNAVAILABLE(503, "Service Unavailable"), GATEWAY_TEIMOUT(504, "Gateway Timeout"),
		HTTP_VERSION_NOT_SUPPORTED(505, "HTTP Version Not Supported"),
		INSUFFICIENT_STORAGE(507, "Insufficient Storage");

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
			return ofString().map(v -> new BigDecimal(v)).orElseThrow();
		}

		default boolean asBoolean() {
			return ofString().map(v -> Boolean.valueOf(v)).orElseThrow();
		}

		default Optional<Boolean> ofBoolean() {
			return ofString().map(v -> Boolean.parseBoolean(v));
		}

		default byte asByte() {
			return ofString().map(v -> Byte.parseByte(v)).orElseThrow();
		}

		@Override
		default ReadableByteChannel asChannel() {
			return Channels.newChannel(asStream());
		}
		
		default char asChar() {
			return ofChar().orElseThrow();
		}
		
		default Optional<Character> ofChar() {
			return ofString().map(v -> v.charAt(0));
		}

		default double asDouble() {
			return ofDouble().orElseThrow();
		}

		default Optional<Double> ofDouble() {
			return ofString().map(v -> Double.parseDouble(v));
		}

		default float asFloat() {
			return ofFloat().orElseThrow();
		}

		default Optional<Float> ofFloat() {
			return ofString().map(v -> Float.parseFloat(v));
		}

		default Instant asInstant() {
			return ofInstant().orElseThrow();
		}

		default Optional<Instant> ofInstant() {
			return ofString().map(v -> parseDate(v).toInstant());
		}

		default int asInt() {
			return ofInt().orElseThrow();
		}

		default Optional<Integer> ofInt() {
			return ofString().map(v -> v.equals("") ? null : Integer.parseInt(v));
		}

		default long asLong() {
			return ofLong().orElseThrow();
		}

		default Optional<Long> ofLong() {
			return ofString().map(v -> Long.parseLong(v));
		}

		@Override
		default Reader asReader() {
			return new StringReader(asString());
		}

		default short asShort() {
			return ofString().map(v -> Short.parseShort(v)).orElseThrow();
		}

		@Override
		default InputStream asStream() {
			return new ByteArrayInputStream(asString().getBytes());
		}

		@Override
		default String asString() {
			return ofString().orElseThrow();
		}

		default boolean hasValue() {
			return ofString().isPresent();
		}

		Optional<String> ofString();
	}

	public final static class ThreadPoolRunnerBuilder {
		private Optional<Integer> threads = Optional.empty();

		public Runner build() {
			return new ThreadPoolRunner(threads);
		}

		public ThreadPoolRunnerBuilder withThreads(int threads) {
			this.threads = Optional.of(threads);
			return this;
		}
	}
	
	public final static class RequestPath {
		
	}

	public final static class Transaction {
		
		public static ThreadLocal<Transaction> current = new ThreadLocal<>();

		private final Client client;

		private Optional<Status> code = Optional.empty();
		private final Optional<String> queryString;
//		private Supplier<Optional<Content>> contentSupplier;
		private final Map<String, Named> incomingHeaders = new LinkedHashMap<>();
		private final Map<String, Cookie> incomingCookies = new LinkedHashMap<>();
		private final List<String> matches = new ArrayList<>();
		private final Method method;
		private Optional<String> responseType = Optional.empty();
		private final Map<String, Named> outgoingHeaders = new LinkedHashMap<>();
		private final Map<String, Cookie> outgoingCookies = new LinkedHashMap<>();
		private final Map<String, Named> parameters = new LinkedHashMap<>();
		private final Stack<Context> contexts = new Stack<>();
		private Path path;
		private Path contextPath;
		private Path fullPath;
		private Optional<Principal> principal = Optional.empty();
		private final Protocol protocol;
		private Optional<BufferFiller> responder = Optional.empty();
		private Optional<Long> responseLength = Optional.empty();
		private Optional<String> responseText = Optional.empty();
		private Optional<HandlerSelector> selector = Optional.empty();
		private final String urlHost;
		private final String uri;
		private Optional<Throwable> error = Optional.empty();
		private Path fullContextPath;
		private WritableByteChannel responseChannel;
		private boolean responseStarted;
		private final ByteChannel delegate;
		private Content content;
		private final Instant timestamp = Instant.now();

		Transaction(String pathSpec, Method method, Protocol protocol, Client client, Writer writer,
				ByteChannel delegate) {
			this.method = method;
			this.delegate = delegate;
			this.protocol = protocol;
			this.client = client;
			this.uri = pathSpec;

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
				queryString = Optional.empty();
			} else {
				path = Paths.get(pathSpec.substring(0, idx));
				queryString = Optional.of(pathSpec.substring(idx + 1));
				parameters.putAll(Named.parseParameters(queryString.get()));
			}

			fullContextPath = contextPath = Paths.get("/");
			fullPath = contextPath.resolve(path);
		}
		
		public static Transaction get() {
			var tx = current.get();
			if(tx == null)
				throw new IllegalStateException("Not a web request thread.");
			return tx;
		}
		
		public Transaction selector(HandlerSelector selector) {
			this.selector = Optional.of(selector);
			return this;
		}

		public final void authenticate(Principal principal) {
			this.principal = Optional.of(principal);
		}

		public final boolean authenticated() {
			return principal.isPresent();
		}
		
		public boolean secure() {
			return client.secure;
		}

		public final Client client() {
			return client;
		}

		public final Context context() {
			return contexts.peek();
		}

		public final Path contextPath() {
			return contextPath;
		}

		public final Transaction cookie(Cookie cookie) {
			checkNotResponded();
			outgoingCookies.put(cookie.name(), cookie);
			return this;
		}

		public final Cookie cookie(String name) {
			return cookieOr(name).orElseThrow();
		}

		public final Transaction cookie(String name, String value) {
			return cookie(UHTTPD.cookie(name, value).build());
		}

		public final Optional<Cookie> cookieOr(String name) {
			return Optional.ofNullable(incomingCookies.get(name));
		}

		public final Optional<Throwable> error() {
			return error;
		}

		public final void error(Throwable ise) {
			checkNotResponded();
			this.error = Optional.of(ise);
			responseCode(Status.INTERNAL_SERVER_ERROR);
			if (ise.getMessage() != null)
				responseText(ise.getMessage());
			responseType("text/plain");
			responseLength = Optional.empty();

		}

		public final Optional<String> errorTrace() {
			return error.map(e -> {
				var sw = new StringWriter();
				e.printStackTrace(new PrintWriter(sw));
				return sw.toString();
			});
		}

		@Deprecated
		public final Transaction found(String location) {
			return redirect(Status.MOVED_PERMANENTLY, location);
		}
		
		public String url() {
			var sb = new StringBuilder();
			if(secure()) 
				sb.append("https://");
			else 
				sb.append("http://");
			sb.append(host());
			var uri = uri();
			if(!uri.equals("/"))
				sb.append(uri);
			return sb.toString();
		}

		public final Path fullContextPath() {
			return fullContextPath;
		}

		public final Path fullPath() {
			return fullPath;
		}

		public final boolean hasResponse() {
			return responder.isPresent() || responseChannel != null;
		}

		public final boolean hasResponseHeader(String name) {
			return outgoingHeaders.containsKey(name);
		}

		public final String header(String name) {
			return headerOr(name).orElseThrow();
		}

		public final Transaction header(String name, String value) {
			checkNotResponded();
			outgoingHeaders.put(name.toLowerCase(), new Named(name.toLowerCase(), value));
			return this;
		}

		public final Optional<String> headerOr(String name) {
			return headersOr(name).map(h -> h.ofString().get());
		}

		public final List<Named> headers() {
			return Collections.unmodifiableList(new ArrayList<>(incomingHeaders.values()));
		}

		public final Named headers(String name) {
			return headersOr(name).orElseThrow();
		}

		public final Optional<Named> headersOr(String name) {
			return incomingHeaders.values().stream().filter(h -> h.name().equals(name.toLowerCase()))
					.map(h -> Optional.of(h)).reduce((f, s) -> f).orElse(Optional.empty());
		}

		public final String remoteAddress() {
			var hdr = headerOr(HDR_X_FORWARDED_FOR);
			return hdr.isPresent() ? hdr.get()
					: client.remoteAddress() instanceof InetSocketAddress
							? ((InetSocketAddress) client.remoteAddress()).getAddress().getHostAddress()
							: client.remoteAddress().toString();
		}

		public final String host() {
			var hdr = headerOr(HDR_X_FORWARDED_HOST).or(() -> headerOr(HDR_HOST));
			return hdr.isPresent() ? hdr.get() : urlHost;
		}

		public final String hostName() {
			var host = host();
			var idx = host.indexOf(':');
			return idx == -1 ? host : host.substring(0, idx);
		}

		public final int hostPort() {
			var host = host();
			var idx = host.indexOf(':');
			return idx == -1 ? client.port() : Integer.parseInt(host.substring(idx + 1));
		}
		
		public String match(int match) {
			return matches.get(match);
		}

		public final List<String> matches() {
			return Collections.unmodifiableList(matches);
		}

		public final Method method() {
			return method;
		}

		public final Transaction notFound() {
			checkNotResponded();
			responseCode(Status.NOT_FOUND);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public final Transaction notImplemented() {
			checkNotResponded();
			responseCode(Status.NOT_IMPLEMENTED);
			responseType("text/plain");
			responseLength = Optional.empty();
			return this;
		}

		public final Named parameter(String name) {
			return parameterOr(name).orElseThrow();
		}

		public final Iterable<String> parameterNames() {
			return parameters.keySet();
		}

		public final Optional<Named> parameterOr(String name) {
			return Optional.ofNullable(parameters.get(name));
		}

		public final Iterable<Named> parameters() {
			return parameters.values();
		}

		public final Stream<Named> parameterStream() {
			return parameters.values().stream();
		}

		public final Path path() {
			return path;
		}

		public final Optional<Principal> principal() {
			return principal;
		}
		
		public final Protocol protocol() {
			return protocol;
		}

		public final Optional<String> queryString() {
			return queryString;
		}

		
		public final Transaction redirect(Status status, Path location) {
			return redirect(status, location.toString());
		}
		
		public final Transaction redirect(Status status, String location) {
			checkNotResponded();
			if (status != Status.MOVED_PERMANENTLY && status != Status.MOVED_TEMPORARILY)
				throw new IllegalArgumentException(MessageFormat.format("May only use {0} or {1}.",
						Status.MOVED_PERMANENTLY, Status.MOVED_TEMPORARILY));
			responseCode(status);
			header("Location", location == null ? "/" : location);
			resetContent();
			return this;
		}

		public final Content request() {
			if (content == null) {
				var chan = delegate;
				var te = headerOr(HDR_TRANSFER_ENCODING);
				var chunk = te.isPresent() && te.get().equals("chunked");
				if (chunk) {
					if (LOG.isLoggable(Level.DEBUG))
						LOG.log(Level.DEBUG, "HTTP IN: Incoming content is chunked");
					chan = new ChunkedChannel(client, chan, StandardOpenOption.READ);
				} else {
					var cl = headersOr(HDR_CONTENT_LENGTH);
					if (cl.isPresent()) {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "HTTP IN: Incoming content has content length of {0}",
									cl.get().asLong());

						chan = new LengthLimitedChannel(client, chan, cl.get().asLong(), StandardOpenOption.READ);
					} else {
						var close = !client.rootContext.keepAlive || Protocol.HTTP_1_1.compareTo(protocol()) > 0
								|| headersOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",")
										.containsIgnoreCase("close");
						if (!close) {
							chan = new LengthLimitedChannel(client, chan, 0, StandardOpenOption.READ);
						}

						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "HTTP IN: Incoming content will end at end of stream");
					}
				}
				var ce = headerOr(HDR_CONTENT_ENCODING);
				var gzip = ce.isPresent() && ce.get().equals("gzip");
				if (gzip) {
					if (LOG.isLoggable(Level.DEBUG))
						LOG.log(Level.DEBUG, "HTTP IN: Incoming content is gzipped");

					try {
						chan = (ByteChannel) Channels.newChannel(new GZIPInputStream(Channels.newInputStream(chan)));
					} catch (IOException e) {
						throw new UncheckedIOException(e);
					}
//					chan = new GZIPChannel(client, chan, StandardOpenOption.READ);
				}
				content = new HTTPContent(this, chan);
			}
			return content;
		}

		public final Transaction resetContent() {
			responder = Optional.empty();
			responseLength = Optional.empty();
			responseType = Optional.empty();
			return this;
		}

		public final Transaction responder(BufferFiller responder) {
			if (method().equals(Method.HEAD))
				throw new IllegalStateException("No response is allowed for HEAD method.");
			checkNotResponded();
			this.responder = Optional.of(responder);
			return this;
		}

		public final Transaction responder(String responseType, BufferFiller responder) {
			if (method().equals(Method.HEAD))
				throw new IllegalStateException("No response is allowed for HEAD method.");
			checkNotResponded();
			responseType(responseType);
			this.responder = Optional.of(responder);
			return this;
		}

		/**
		 * Respond with a generic object. This method supports a few basic types, with
		 * everything else being converted to a string using {@link Object#toString()}.
		 * If the response is an {@link InputStream} or a {@link Reader}, it's contents
		 * will be streamed. If it is a {@link ByteBuffer}, it will be transferred as
		 * is. All other types will be converted.
		 * <p>
		 * If there is no {@link #responseLength(long)} set, then attempts will be made
		 * to set it from the content. This can be done up front with a
		 * {@link ByteBuffer} or other non-streamed type.
		 *
		 * @param response
		 * @return this for chaining.
		 */
		public final Transaction response(Object response) {
			return responder(new DefaultResponder(response, this));
		}

		public final Transaction response(String responseType, Object response) {
			if (method().equals(Method.HEAD))
				throw new IllegalStateException("No response is allowed for HEAD method.");
			responseType(responseType);
			return response(response);
		}
		
		public Instant timestamp() {
			return timestamp;
		}
		
		public final Optional<Status> responseCode() {
			return code;
		}

		public final Transaction responseCode(Status code) {
			checkNotResponded();
			this.code = Optional.of(code);
			return this;
		}

		@Deprecated
		public final boolean responsed() {
			return code.isPresent();
		}

		public final boolean responded() {
			return code.isPresent();
		}

		public final Optional<Long> responseLength() {
			return responseLength;
		}
		
		public final Transaction responseLength(long responseLength) {
			checkNotResponded();
			this.responseLength = responseLength == -1 ? Optional.empty() : Optional.of(responseLength);
			return this;
		}
		
		public final Optional<String> responseText() {
			return responseText;
		}

		public final Transaction responseText(String text) {
			checkNotResponded();
			this.responseText = Optional.of(text);
			return this;
		}

		public final Optional<String> responseType() {
			return responseType;
		}

		public final Transaction responseType(String contentType) {
			checkNotResponded();
			responseType = Optional.ofNullable(contentType);
			return this;
		}

		public final WritableByteChannel responseWriter() {
			if (responseChannel == null) {
				responseChannel = new WritableByteChannel() {

					private WritableByteChannel output;

					@Override
					public void close() throws IOException {
						output.close();
					}

					@Override
					public boolean isOpen() {
						return output.isOpen();
					}

					@Override
					public int write(ByteBuffer src) throws IOException {
						if (output == null)
							output = client.wireProtocol.responseWriter(Transaction.this);
						responseStarted = true;
						return output.write(src);
					}

				};
			}
			return responseChannel;
		}

		public final HandlerSelector selector() {
			return selector.orElseThrow();
		}

		public final Optional<HandlerSelector> selectorOr() {
			return selector;
		}

		@Override
		public String toString() {
			return "Request [path=" + path + ", parameters=" + parameters + ", incomingHeaders=" + incomingHeaders
					+ ", outgoingHeaders=" + outgoingHeaders + ", outgoingContentLength=" + responseLength
					+ ", outgoingContentType=" + responseType + /* ", response=" + response + */ ", code=" + code
					+ ", responseText=" + responseText + ", principal=" + principal + ", method=" + method
					+ ", protocol=" + protocol + ", urlHost=" + urlHost + "]";
		}

		public Transaction unauthorized(String realm) {
			checkNotResponded();
			responseCode(Status.UNAUTHORIZED);
			responseType("text/plain");
			header("WWW-Authenticate", String.format("Basic realm=\"%s\"", realm));
			responseLength = Optional.empty();
			return this;

		}

		public final String uri() {
			return uri;
		}

		void checkNotResponded() {
			if (responseStarted)
				throw new IllegalStateException("Response already started.");
		}

		void pushContext(Context context, String ctxPath, String resPath) {
			this.contexts.push(context);
			contextPath = Paths.get(ctxPath);
			path = Paths.get(resPath);
			fullContextPath = fullContextPath.resolve(ctxPath.substring(1));
			fullPath = fullContextPath.resolve(resPath.substring(1));
		}
	}

	public final static class TunnelBuilder {
		private Optional<BufferFiller> reader = Optional.empty();
		private Optional<BufferFiller> writer = Optional.empty();
		private Optional<Runnable> onClose = Optional.empty();
		private Optional<Integer> bufferSize = Optional.empty();

		public TunnelHandler build() {
			return new AbstractTunnelHandler() {
				@Override
				com.sshtools.uhttpd.UHTTPD.AbstractTunnelHandler.TunnelWireProtocol create(String host, int port,
						Client client) throws IOException {
					return new TunnelWireProtocol(bufferSize, reader.orElseThrow(), writer.orElseThrow(), onClose,
							client);
				}
			};
		}

		public TunnelBuilder onClose(Runnable onClose) {
			this.onClose = Optional.of(onClose);
			return this;
		}

		public TunnelBuilder withBufferSize(int bufferSize) {
			this.bufferSize = Optional.of(bufferSize);
			return this;
		}

		public TunnelBuilder withReader(BufferFiller reader) {
			this.reader = Optional.of(reader);
			return this;
		}

		public TunnelBuilder withWriter(BufferFiller writer) {
			this.writer = Optional.of(writer);
			return this;
		}
	}

	public interface TunnelHandler extends Handler {

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
	
	public interface GroupBuilder<T extends GroupBuilder<T, C>, C extends Group> {

		C build() throws IOException;

		T status(Status status, Handler handler);

	}

	public interface WebContextBuilder<T extends WebContextBuilder<T, C>, C extends Context> extends GroupBuilder<T, C> {

		T chain(Handler... handlers);

		T classpathResources(String regexpWithGroups, Handler... handler);

		T classpathResources(String regexpWithGroups, String prefix, Handler... handler);

		T context(Handler... handlers);

		T delete(String regexp, Handler... handler);

		T fileResources(String regexpWithGroups, Path root, Handler... handler);

		T get(String regexp, Handler... handler);

		T handle(HandlerSelector selector, Handler... handler);

		T handle(String regexp, Handler... handler);

		T post(String regexp, Handler... handler);

		T tunnel(TunnelHandler handler);

		T webSocket(String regexp, WebSocketHandler handler);

		T withClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader, String prefix,
				Handler... handler);

		T withFileResources(String regexpWithGroups, Path root, Handler... handler);

		T withETagGenerator(Function<Path, String> etagCalculator);

		T withTmpDir(Path tmpDir);

		T withLogger(Consumer<Transaction> logger);
	}

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
	 */
	public interface WebSocket extends Closeable {
		Client client();

		void fragment(ByteBuffer data, boolean finalFrame) throws UncheckedIOException;

		String protocol();

		default void send(ByteBuffer data) throws UncheckedIOException {
			fragment(data, true);
		}

		void send(String data) throws UncheckedIOException;

		int version();
	}

	public static final class WebSocketBuilder {
		private Optional<OnWebSocketClose> onClose = Optional.empty();
		private Optional<OnWebSocketData> onData = Optional.empty();
		private Optional<OnWebSocketText> onText = Optional.empty();
		private Optional<OnWebSocketHandshake> onHandshake = Optional.empty();
		private Optional<OnWebSocketOpen> onOpen = Optional.empty();
		private Optional<Integer> maxTextPayloadSize = Optional.empty();

		public WebSocketHandler build() {
			return new WebSocketHandler(this);
		}

		public WebSocketBuilder onClose(OnWebSocketClose onClose) {
			this.onClose = Optional.of(onClose);
			return this;
		}

		public WebSocketBuilder onData(OnWebSocketData onData) {
			this.onData = Optional.of(onData);
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

		public WebSocketBuilder onText(OnWebSocketText onText) {
			this.onText = Optional.of(onText);
			return this;
		}

		public WebSocketBuilder withMaxTextPayloadSize(int maxTextPayloadSize) {
			this.maxTextPayloadSize = Optional.of(maxTextPayloadSize);
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

			abstract void read(WebSocketImpl ws, WebSocketFrame frame, ByteChannel channel) throws IOException;

		}

		private class BinaryMessage extends AbstractIncomingMessage {

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, ByteChannel channel) {
				onData.ifPresent(c -> c.receive(frame.payload, frame.fin, ws));
			}
		}

		private final class CloseMessage extends AbstractIncomingMessage {

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, ByteChannel channel) throws IOException {
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
			void read(WebSocketImpl ws, WebSocketFrame frame, ByteChannel channel) throws IOException {
				if (!frame.fin)
					throw new IllegalStateException("Control frames must not be fragment.");
				var pongFrame = new WebSocketFrame(OpCode.PONG, frame.payload, true, frame.mask, frame.key);
				pongFrame.write(channel);
			}
		}

		private class TextMessage extends AbstractIncomingMessage {

			CharsetDecoder dec;
			CharBuffer out;

			@Override
			void read(WebSocketImpl ws, WebSocketFrame frame, ByteChannel channel) {

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

			ByteBuffer buffer = ByteBuffer.allocate(14); // enough for header
			boolean fin, rsv1, rsv2, rsv3, mask;
			byte[] key;
			OpCode opCode;

			ByteBuffer payload; // TODO reuse buffer

			WebSocketFrame() {
			}

			WebSocketFrame(OpCode opCode, ByteBuffer payload, boolean fin) {
				this(opCode, payload, fin, false, null);
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

			void read(ByteChannel channel) throws IOException {
				buffer.clear();
				var read = channel.read(buffer);
				if(read == -1)
					throw new EOFException();
					
				buffer.flip();

				if (LOG.isLoggable(Level.TRACE))
					debugByteBuffer("Frame", buffer);

				var b1 = buffer.get();

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
				if(!mask) {
					throw new IOException("Client to server messages should be masked.");
				}
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

			void write(ByteChannel channel) throws IOException {

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
			public void fragment(ByteBuffer data, boolean finalPacket) {
				var frame = new WebSocketFrame(OpCode.BINARY, data, finalPacket);
				try {
					frame.write(client.channel());
				} catch (IOException e) {
					throw new UncheckedIOException("Failed to send websocket text.", e);
				}
			}

			@Override
			public String protocol() {
				return selectedProtocol;
			}

			@Override
			public void send(String data) throws UncheckedIOException {
				var enc = client.charset().newEncoder();
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
						if (closed)
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
				} catch(EOFException ioe) {
					LOG.log(Level.TRACE, "WebSocket EOF.", ioe);
				} catch(IOException ioe) {
					LOG.log(Level.WARNING, "I/O error in WebSocket.", ioe);
				} catch(RuntimeException ioe) {
					LOG.log(Level.ERROR, "Error in WebSocket handling.", ioe);
				}
				finally {
					if (!closed)
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

		public WebSocketHandler(WebSocketBuilder builder) {
			this.onData = builder.onData;
			this.onText = builder.onText;
			this.onClose = builder.onClose;
			this.onOpen = builder.onOpen;
			this.onHandshake = builder.onHandshake;
			this.maxTextPayloadSize = builder.maxTextPayloadSize.orElse(DEFAULT_BUFFER_SIZE);
		}

		@Override
		public void get(Transaction req) throws Exception {
			if (req.headersOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").contains("Upgrade")
					&& req.headerOr(HDR_UPGRADE).orElse("").equalsIgnoreCase("websocket")) {
				// TODO https://en.wikipedia.org/wiki/WebSocket

				// TODO origin check

				var keyOr = req.headerOr("sec-websocket-key");
				var proto = req.headersOr("sec-websocket-protocol");
				var version = req.headers("sec-websocket-version").asInt();
				if (version > SUPPORTED_WEBSOCKET_VERSION) {
					req.header("sec-websocket-version", String.valueOf(SUPPORTED_WEBSOCKET_VERSION));
					req.responseCode(Status.UPGRADE_REQUIRED);
					return;
				}
				var hasher = MessageDigest.getInstance("SHA-1");
				
				var requestedProtocols = proto.map(n -> n.expand(",").values()).orElse(Collections.emptyList());
				
				var selectedProtocol = onHandshake.isPresent() ?
						onHandshake.get().handshake(req, requestedProtocols.toArray(new String[0])) :
						( requestedProtocols.isEmpty() ? "" : requestedProtocols.get(0)	);
				
				var client = req.client();

				var ws = new WebSocketImpl(client, selectedProtocol, version);

				req.responseCode(Status.SWITCHING_PROTOCOLS);
				req.header(HDR_CONNECTION, "Upgrade");
				req.header(HDR_UPGRADE, "websocket");
				if (!selectedProtocol.equals(""))
					req.header("sec-websocket-protocol", selectedProtocol);
				
				if(keyOr.isPresent()) {
					var key = keyOr.get();
					if(key.length() != 24) {
						ws.close();
						throw new IOException("invalid Sec-WebSocket-Key header");
					}
					var responseKeyData = key + WEBSOCKET_UUID;
					var responseKeyBytes = responseKeyData.getBytes("UTF-8");
					var responseKey = Base64.getEncoder().encodeToString(hasher.digest(responseKeyBytes));
					req.header("sec-websocket-accept", responseKey);
				}

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

		default WritableByteChannel responseWriter(Transaction tx) throws IOException {
			throw new UnsupportedOperationException();
		}

		void transact() throws IOException;
	}
	
	public abstract static class AbstractGroup implements Group {
		
		protected final Map<Status, Handler> statusHandlers = new LinkedHashMap<>();
		
		protected abstract Collection<? extends Handler> handlers();
		
		protected AbstractGroup(AbstractGroupBuilder<?, ?> b) {
			statusHandlers.putAll(b.statusHandlers);
		}
		
		@Override
		public final void close() {
			handlers().forEach(h -> { 
				if(h instanceof Context) 
					((Context)h).close();	
			});
			onClose();
		}
		
		protected void onClose() {
		}
		

		boolean handleStatus(Transaction tx) {
			
			for (var c : handlers()) {
				if (c instanceof AbstractGroup) {
					if(((AbstractGroup)c).handleStatus(tx)) {
						return true;
					}
				}
			}
			
			while (true) {
				var code = tx.code.orElse(Status.OK);
				var statusHandler = statusHandlers.get(code);
				if (statusHandler == null) {
					break;
				} else {
					try {
						statusHandler.get(tx);
						return true;
					} catch (Exception e) {
						LOG.log(Level.ERROR, "Status handler failed.", e);
						if(code == Status.INTERNAL_SERVER_ERROR) 
							break;
						else
							tx.error(e);
					}
				}
			}
			
			return false;
			
		}
	}

	public abstract static class AbstractContext extends AbstractGroup implements Context {
		protected final Map<HandlerSelector, Handler> handlers = new LinkedHashMap<>();
		protected Optional<Function<Path, String>> etagGenerator;
		protected AbstractContext parent;
		protected final Path tmpDir;
		protected final boolean clearTmpDirOnClose;
		protected final Optional<Consumer<Transaction>> logger;

		protected AbstractContext(AbstractWebContextBuilder<?, ?> b) {
			super(b);
			handlers.putAll(b.handlers);
			etagGenerator = b.etagGenerator;
			logger = b.logger;

			handlers.forEach((k, v) -> {
				if (v instanceof AbstractContext) {
					((AbstractContext) v).parent = this;
				}
			});
			clearTmpDirOnClose = b.tmpDir.isEmpty();
			try {
				tmpDir = b.tmpDir.orElse(Files.createTempDirectory("uhttpd"));
			} catch (IOException e) {
				throw new UncheckedIOException("Failed to create temporary directory.", e);
			}
		}

		@Override
		protected Collection<? extends Handler> handlers() {
			return handlers.values();
		}

		@Override
		protected void onClose() {
			if (clearTmpDirOnClose) {
				try (var walk = Files.walk(tmpDir)) {
					walk.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
				}
				catch(IOException ioe) {
					throw new UncheckedIOException(ioe);
				}
			}
		}

		@Override
		public String generateETag(Path resource) {
			return generateETag(this, resource);
		}

		@Override
		public Path tmpDir() {
			return tmpDir;
		}

		String generateETag(AbstractContext ctx, Path resource) {
			var o = ctx.etagGenerator;
			if (o.isPresent())
				return o.get().apply(resource);
			else {
				if (parent == null) {
					try {
						long contentLength = Files.size(resource);
						long lastModified = Files.getLastModifiedTime(resource).toMillis();
						if ((contentLength >= 0) || (lastModified >= 0)) {
							return "W/\"" + contentLength + "-" + lastModified + "\"";
						}
					} catch (IOException ioe) {
						LOG.log(Level.ERROR, "Failed to generate etag.", ioe);
					}
					return null;
				} else
					return generateETag(parent, resource);
			}
		}
	}

	private static abstract class AbstractTunnelHandler implements TunnelHandler {

		class TunnelWireProtocol implements WireProtocol {

			private final ByteBuffer sndBuf;
			private final ByteBuffer recvBuf;
			private final Client client;
			private final BufferFiller reader;
			private final BufferFiller writer;
			private final Optional<Runnable> close;
			private AtomicBoolean closed = new AtomicBoolean();

			TunnelWireProtocol(Optional<Integer> bufferSize, BufferFiller reader, BufferFiller writer,
					Optional<Runnable> close, Client client) {
				this.client = client;
				this.reader = reader;
				this.writer = writer;
				this.close = close;

				sndBuf = ByteBuffer.allocateDirect(bufferSize.orElse(DEFAULT_BUFFER_SIZE));
				recvBuf = ByteBuffer.allocateDirect(bufferSize.orElse(DEFAULT_BUFFER_SIZE));
			}

			@Override
			public void transact() throws IOException {
				client.rootContext.runner.run(() -> {
					try {
						while (true) {
							if (LOG.isLoggable(Level.TRACE))
								LOG.log(Level.TRACE, "Tunnel HTTP receiving thread waiting data.");
							client.channel.read(recvBuf);
							if (recvBuf.position() == 0)
								break;
							if (LOG.isLoggable(Level.TRACE))
								LOG.log(Level.TRACE, "Tunnel HTTP receiving thread got {0} bytes.", recvBuf.position());
							recvBuf.flip();
							writer.supply(recvBuf);
							if (LOG.isLoggable(Level.TRACE))
								LOG.log(Level.TRACE, "Tunnel HTTP receiving passed on {0} bytes.", recvBuf.position());
							recvBuf.flip();
						}
					} catch (ClosedChannelException eof) {
						if (LOG.isLoggable(Level.TRACE))
							LOG.log(Level.TRACE, "Receiver closed.");
					} catch (IOException ioe) {
						LOG.log(Level.ERROR, "HTTP Receiving thread failed.", ioe);
					} finally {
						if (!closed.getAndSet(true)) {
							close.ifPresent(c -> c.run());
						}
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Tunnel HTTP receiving thread done");
					}
				});
				try {
					while (true) {
						if (LOG.isLoggable(Level.TRACE))
							LOG.log(Level.TRACE, "Tunnel HTTP sending thread waiting data.");
						reader.supply(sndBuf);
						if (sndBuf.position() == 0)
							break;
						if (LOG.isLoggable(Level.TRACE))
							LOG.log(Level.TRACE, "Tunnel HTTP sending thread got {0} bytes.", sndBuf.position());
						sndBuf.flip();
						client.channel.write(sndBuf);
						if (LOG.isLoggable(Level.TRACE))
							LOG.log(Level.TRACE, "Tunnel HTTP sending passed on {0} bytes.", sndBuf.position());
						sndBuf.flip();
					}
				} catch (ClosedChannelException ace) {
					if (LOG.isLoggable(Level.TRACE))
						LOG.log(Level.TRACE, "Sender closed.");
				} finally {
					if (!closed.getAndSet(true)) {
						close.ifPresent(c -> c.run());
					}
					if (LOG.isLoggable(Level.DEBUG))
						LOG.log(Level.DEBUG, "Tunnel HTTP sending thread done");
				}
				throw new EOFException();
			}
		}

		@Override
		public final void get(Transaction tx) throws Exception {
			// https://en.wikipedia.org/wiki/HTTP_tunnel
			// TODO - proxy auth
			tx.responseCode(Status.OK);
			var target = tx.uri().split(":");
			if (LOG.isLoggable(Level.DEBUG))
				LOG.log(Level.DEBUG, "Opening tunnel to {0}", tx.uri());
			tx.client.wireProtocol = create(target[0], Integer.parseInt(target[1]), tx.client());
		}

		abstract TunnelWireProtocol create(String host, int port, Client client) throws IOException;
	}
	
	public static abstract class AbstractGroupBuilder<T extends AbstractGroupBuilder<T, G>, G extends Group>
			implements GroupBuilder<T, G> {
		Map<Status, Handler> statusHandlers = new LinkedHashMap<>();

		protected AbstractGroupBuilder() {
		}

		@SuppressWarnings("unchecked")
		public T status(Status status, Handler handler) {
			statusHandlers.put(status, handler);
			return (T) this;
		}

	}

	public static abstract class AbstractWebContextBuilder<T extends AbstractWebContextBuilder<T, C>, C extends Context>
			extends AbstractGroupBuilder<T, C> implements WebContextBuilder<T, C> {
		Map<HandlerSelector, Handler> handlers = new LinkedHashMap<>();
		Optional<Function<Path, String>> etagGenerator;
		Optional<Path> tmpDir = Optional.empty();
		Optional<Consumer<Transaction>> logger = Optional.empty();

		protected AbstractWebContextBuilder() {
		}

		@Override
		@SuppressWarnings("unchecked")
		public T chain(Handler... handlers) {
			handle(ALL_SELECTOR, (req) -> {
				for (var h : handlers) {
					h.get(req);
					if (req.responsed())
						break;
				}
			});
			return (T) this;
		}

		@Override
		public T classpathResources(String regexpWithGroups, Handler... handler) {
			return classpathResources(regexpWithGroups, "", handler);
		}

		@Override
		public T classpathResources(String regexpWithGroups, String prefix, Handler... handler) {
			return withClasspathResources(regexpWithGroups,
					Optional.ofNullable(UHTTPD.class.getClassLoader()), prefix, handler);
		}

		@Override
		public T context(Handler... handlers) {
			if (handlers.length == 0 || !(handlers[handlers.length - 1] instanceof Context)) {
				throw new IllegalArgumentException(
						MessageFormat.format("The last handler must be a {0}", Context.class.getName()));
			}
			var ctx = (Context) handlers[handlers.length - 1];
			return handle(new RegularExpressionSelector(((ContextImpl) ctx).pathExpression), handlers);
		}

		@Override
		public T delete(String regexp, Handler... handler) {
			return handle(
					new CompoundSelector(new MethodSelector(Method.DELETE), new RegularExpressionSelector(regexp)),
					handler);
		}

		@Override
		@SuppressWarnings("unchecked")
		public T fileResources(String regexpWithGroups, Path root, Handler... handler) {
			var l = new ArrayList<Handler>();
			l.add(new FileResources(regexpWithGroups, root));
			l.addAll(Arrays.asList(handler));
			handle(new RegularExpressionSelector(regexpWithGroups), l.toArray(new Handler[0]));
			return (T) this;
		}

		@Override
		public T get(String regexp, Handler... handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.GET), new RegularExpressionSelector(regexp)),
					handler);
		}

		@Override
		@SuppressWarnings("unchecked")
		public T handle(HandlerSelector selector, Handler... handler) {
			if (handler.length == 0)
				throw new IllegalArgumentException("Expect at least one handler.");
			if (handler.length == 1)
				handlers.put(selector, handler[0]);
			else {
				var bldr = new HandlerGroup.HandlerGroupBuilder();
				for(var h : handler) 
					bldr.handle(h);
				handlers.put(selector, bldr.build());
			}
			return (T) this;
		}

		@Override
		public T handle(String regexp, Handler... handler) {
			return handle(new RegularExpressionSelector(regexp), handler);
		}

		@Override
		public T post(String regexp, Handler... handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.POST), new RegularExpressionSelector(regexp)),
					handler);
		}

		@Override
		public T tunnel(TunnelHandler handler) {
			return handle(new MethodSelector(Method.CONNECT), handler);
		}

		@Override
		public T webSocket(String regexp, WebSocketHandler handler) {
			return handle(new CompoundSelector(new MethodSelector(Method.GET), new RegularExpressionSelector(regexp)),
					handler);
		}

		public T withClasspathResources(String regexpWithGroups, ClassLoader loader, String prefix,
				Handler... handler) {
			return withClasspathResources(regexpWithGroups, Optional.of(loader), prefix, handler);
		}

		@Override
		@SuppressWarnings("unchecked")
		public T withClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader, String prefix,
				Handler... handler) {
			var l = new ArrayList<Handler>();
			l.add(UHTTPD.classpathResources(regexpWithGroups, loader, prefix));
			l.addAll(Arrays.asList(handler));
			handle(new RegularExpressionSelector(regexpWithGroups), l.toArray(new Handler[0]));
			return (T) this;
		}

		@Override
		@SuppressWarnings("unchecked")
		public T withFileResources(String regexpWithGroups, Path root,
				Handler... handler) {
			var l = new ArrayList<Handler>();
			l.add(UHTTPD.fileResources(regexpWithGroups, root));
			l.addAll(Arrays.asList(handler));
			handle(new RegularExpressionSelector(regexpWithGroups), l.toArray(new Handler[0]));
			return (T) this;
		}

		@SuppressWarnings("unchecked")
		@Override
		public T withETagGenerator(Function<Path, String> etagGenerator) {
			this.etagGenerator = Optional.of(etagGenerator);
			return (T) this;
		}

		@SuppressWarnings("unchecked")
		@Override
		public T withTmpDir(Path tmpDir) {
			this.tmpDir = Optional.of(tmpDir);
			return (T) this;
		}

		@SuppressWarnings("unchecked")
		@Override
		public T withLogger(Consumer<Transaction> logger) {
			this.logger = Optional.of(logger);
			return (T) this;
		}

	}

	private final static class ChunkedChannel extends WebChannel {

		private long chunkRemain = -1;

		public ChunkedChannel(Client client, ByteChannel delegate, OpenOption... options) {
			super(client, delegate, options);
		}

		@Override
		public void close() throws IOException {
			if (options.contains(StandardOpenOption.WRITE)) {
				writer();
				writer.println("0"); // terminating chunk
				writer.println(); // end of chunking
				writer.flush();
			}
			super.close();
		}

		@Override
		public int read(ByteBuffer dst) throws IOException {
			if (chunkRemain < 1) {
				chunkRemain = Long.parseLong(readLine(), 16);
				if (chunkRemain == 0)
					readLine();
				return -1;
			}
			var read = delegate.read(dst);
			if (read != -1) {
				chunkRemain -= read;
			}
			return read;
		}

		@Override
		public int write(ByteBuffer src) throws IOException {
			if (LOG.isLoggable(Level.DEBUG))
				LOG.log(Level.DEBUG, "Writing chunk of {0} bytes.", src.limit());
			var writer = writer();
			writer.println(Integer.toHexString(src.limit()));
			writer.flush();
			int res = delegate.write(src);
			writer.println();
			writer.flush();
			return res;
		}

	}

	private final static class ClasspathResource implements Handler {

		private final Optional<ClassLoader> loader;
		private final Optional<Class<?>> base;
		private final String path;

		private ClasspathResource(Optional<ClassLoader> loader, Optional<Class<?>> base,String path) {
			this.loader = loader;
			this.path = path;
			this.base = base;
		}

		@Override
		public void get(Transaction req) throws Exception {
			LOG.log(Level.DEBUG, "Locating resource for {0}", path);
			var fullPath = Paths.get(path).normalize().toString();
			var url = base.map(c -> c.getResource(path)).orElseGet(() -> loader.orElse(ClasspathResources.class.getClassLoader()).getResource(fullPath));
			if (url == null)
				throw new FileNotFoundException(fullPath);
			else {
				urlResource(url).get(req);
			}
		}

	}

	private final static class ClasspathResources implements Handler {

		private Optional<ClassLoader> loader;
		private final String prefix;
		private final Pattern regexpWithGroups;

		private ClasspathResources(String regexpWithGroups, Optional<ClassLoader> loader, String prefix) {
			this.loader = loader;
			this.prefix = prefix;
			this.regexpWithGroups = Pattern.compile(regexpWithGroups);
		}

		@Override
		public void get(Transaction req) throws Exception {
			var matcher = regexpWithGroups.matcher(req.path().toString());
			if (matcher.find()) {
				var path = prefix;
				if(!path.equals("") && !path.endsWith("/"))
					path += "/";
				var match = matcher.group(1);
				while(match.startsWith("/"))
					match = match.substring(1);
				classpathResource(loader, path + match).get(req);
			} else
				throw new IllegalStateException(
						String.format("Handling a request where the pattern '%s' does not match the path '%s'",
								regexpWithGroups, req.path()));
		}

	}

	private final static class ContextImpl extends AbstractContext {
		final String pathExpression;
		final Pattern pathPattern;

		ContextImpl(ContextBuilder contextBuilder) {
			super(contextBuilder);
			pathExpression = contextBuilder.pathExpression;
			this.pathPattern = Pattern.compile(pathExpression);
		}

		@Override
		public void get(Transaction tx) throws Exception {

			var matcher = pathPattern.matcher(tx.path().toString());
			if (matcher.find()) {
				var fullPath = matcher.group(0);
				var matchedPath = matcher.group(1);
				var ctxPath = fullPath.substring(0, fullPath.length() - matchedPath.length() - 1);
				var resPath = fullPath.substring(fullPath.length() - matchedPath.length() - 1);
				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Path reduced from {0} to context {1} with path {2}", tx.path, ctxPath,
							resPath);

				tx.pushContext(this, ctxPath, resPath);
			}

			for (var c : handlers.entrySet()) {
				if (c.getKey().matches(tx)) {
					tx.selector = Optional.of(c.getKey());
					try {
						c.getValue().get(tx);
						if (!tx.responded() && !tx.hasResponse())
							tx.responseCode(Status.OK);
					} catch (FileNotFoundException fnfe) {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "File not found. {0}", fnfe.getMessage());
						tx.notFound();
					} catch (Exception ise) {
						LOG.log(Level.ERROR, "Request handling failed.", ise);
						tx.error(ise);
					}

					if (tx.responded() || tx.hasResponse())
						break;
				}
			}

			if (tx.code.isEmpty() && !tx.hasResponse()) {
				tx.notFound();
			}
		}
	}

	/**
	 * A factory for {@link SimpleDateFormat}s. The instances are stored in a
	 * threadlocal way because SimpleDateFormat is not threadsafe as noted in
	 * {@link SimpleDateFormat its javadoc}.
	 *
	 */
	private final static class DateFormatHolder {

		private static final ThreadLocal<SoftReference<Map<String, SimpleDateFormat>>> THREADLOCAL_FORMATS = new ThreadLocal<>();

		/**
		 * creates a {@link SimpleDateFormat} for the requested format string.
		 *
		 * @param pattern a non-{@code null} format String according to
		 *                {@link SimpleDateFormat}. The format is not checked against
		 *                {@code null} since all paths go through {@link DateUtils}.
		 * @return the requested format. This simple dateformat should not be used to
		 *         {@link SimpleDateFormat#applyPattern(String) apply} to a different
		 *         pattern.
		 */
		public static SimpleDateFormat formatFor(final String pattern) {
			final SoftReference<Map<String, SimpleDateFormat>> ref = THREADLOCAL_FORMATS.get();
			Map<String, SimpleDateFormat> formats = ref == null ? null : ref.get();
			if (formats == null) {
				formats = new HashMap<>();
				THREADLOCAL_FORMATS.set(new SoftReference<>(formats));
			}

			SimpleDateFormat format = formats.get(pattern);
			if (format == null) {
				format = new SimpleDateFormat(pattern, Locale.US);
				format.setTimeZone(TimeZone.getTimeZone("GMT"));
				formats.put(pattern, format);
			}

			return format;
		}

	}

	private final static class DefaultResponder implements BufferFiller {

		private final Object response;
		private final Charset charset;
		private final boolean needLength;
		private CharsetEncoder enc;
		private final Transaction tx;
		private CharBuffer charBuffer;

		DefaultResponder(Object response, Transaction tx) {
			this.charset = tx.client.charset();
			var needLength = tx.responseLength.isEmpty();
			var needType = tx.responseType.isEmpty();
			if (response instanceof Path) {
				var path = (Path) response;
				try {
					// response = Files.newInputStream(path);
					response = Files.newByteChannel(path);
					if (needLength) {
						tx.responseLength(Files.size(path));
						needLength = false;
					}
					if (needType)
						tx.responseType = Optional.ofNullable(mimeType(path.toUri().toURL()));
				} catch (IOException ioe) {
					throw new UncheckedIOException("Failed to responsd with file.", ioe);
				}
			} else if (response instanceof File) {
				var path = (File) response;
				try {
					// response = new FileInputStream(path);
					response = Files.newByteChannel(path.toPath());
					if (needLength) {
						tx.responseLength(path.length());
						needLength = false;
					}
					if (needType)
						tx.responseType = Optional.ofNullable(mimeType(path.toURI().toURL()));
				} catch (IOException ioe) {
					throw new UncheckedIOException("Failed to responsd with file.", ioe);
				}
			} else if (response instanceof ByteBuffer) {
				if (needLength) {
					needLength = false;
					tx.responseLength(((ByteBuffer) response).remaining());
				}
			} else if (!(response instanceof InputStream) && !(response instanceof Reader)
					&& !(response instanceof ReadableByteChannel)) {
				response = ByteBuffer.wrap(String.valueOf(response).getBytes(charset));
				if (needLength) {
					needLength = false;
					tx.responseLength = Optional.of((long) ((ByteBuffer) response).remaining());
				}
			}

			this.tx = tx;
			this.response = response;
			this.needLength = needLength;
		}

		@Override
		public void close() throws IOException {
			if (response instanceof Closeable) {
				((Closeable) response).close();
			}
		}

		@Override
		public void supply(ByteBuffer buf) throws IOException {
			if (response instanceof ReadableByteChannel) {
				var chan = (ReadableByteChannel) response;
				chan.read(buf);
			} else if (response instanceof ByteBuffer) {
				var respBuff = (ByteBuffer) response;
				if (respBuff.hasRemaining()) {
					if (respBuff.remaining() > buf.remaining()) {
						var waslimit = respBuff.limit();
						respBuff.limit(respBuff.position() + buf.remaining());
						buf.put(respBuff);
						respBuff.limit(waslimit);

//						var p = respBuff.position();
//						respBuff.position(p + buf.remaining());
//						respBuff = respBuff.slice(p, buf.remaining());
					} else
						buf.put(respBuff);
				}
			} else if (response instanceof Reader) {
				if (enc == null) {
					enc = charset.newEncoder();
				}
				if (charBuffer == null) {
					charBuffer = CharBuffer.allocate(buf.remaining() * 2);
				}
				var encoded = enc.encode(charBuffer);
				if (encoded.hasRemaining()) {
					if (needLength) {
						tx.responseLength = Optional.of(tx.responseLength.orElse(0l) + encoded.remaining());
					}
					buf.put(encoded);
				}
			} else if (response instanceof InputStream) {
				var in = (InputStream) response;
				byte[] arr;
				int off = 0;
				if (buf.isDirect()) {
					arr = new byte[buf.remaining()];
				} else {
					arr = buf.array();
					off = buf.arrayOffset();
				}
				var read = in.read(arr, off, arr.length - off);
				if (read != -1) {
					if (needLength) {
						tx.responseLength = Optional.of(tx.responseLength.orElse(0l) + read);
					}
					if (buf.isDirect()) {
						buf.put(arr, 0, read);
					}
				}
			} else
				throw new UnsupportedOperationException();
		}

	}

	private final static class FileResource implements Handler {

		private Path file;

		private FileResource(Path file) {
			this.file = file;
		}

		@Override
		public void get(Transaction req) throws Exception {
			LOG.log(Level.DEBUG, "File resource {0}", file);
			req.responseLength(Files.size(file));
			req.responseType(mimeType(file.toUri().toURL()));
			req.response(Files.newInputStream(file));
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
				LOG.log(Level.DEBUG, "Locating resource for {0}", path);
				if (Files.exists(fullPath)) {
					if (!Files.isDirectory(fullPath)) {
						LOG.log(Level.DEBUG, "Located resource for {0}", fullPath);
						fileResource(fullPath).get(req);
					}
				} else
					throw new FileNotFoundException(fullPath.toString());
			} else
				throw new IllegalStateException(
						String.format("Handling a request where the pattern '%s' does not match the path '%s'",
								regexpWithGroups, req.path()));
		}

	}

	private static final class HTTP11WireProtocol extends WebChannel implements WireProtocol {

		private boolean close;
		private boolean chunk;
		private boolean gzip;
		private WritableByteChannel responseWriter;
		private long responseLength;
		private boolean useLength;
		private boolean responseBigEnoughToCompress;
		private boolean haveLength;

		HTTP11WireProtocol(Client client) {
			super(client, client.channel(), StandardOpenOption.READ, StandardOpenOption.WRITE);
			reset();
		}

		@SuppressWarnings("resource")
		@Override
		public WritableByteChannel responseWriter(Transaction tx) throws IOException {
			if (responseWriter == null) {
				calcResponseLengthAndType(tx);
				var out = client.channel();
				WritableByteChannel nioChan = new PsuedoCloseByteChannel() {
					@Override
					protected int writeImpl(ByteBuffer src) throws IOException {
						var r = out.write(src);
						return r;
					}
				};

				if (haveLength && responseLength < client.rootContext.maxUnchunkedSize) {
					if (gzip) {
						var buf = ByteBuffer.allocateDirect((int) (responseLength * 2)); /* TODO ... improve */
						WritableByteChannel bufchan = new ByteChannel() {

							boolean closed;

							@Override
							public void close() throws IOException {
								if (isOpen()) {
									closed = true;
									useLength = true;
									responseLength = buf.position();
									buf.flip();
									calcChunkingAndClose(tx);
									respondWithHeaders(tx);
									try {
										nioChan.write(buf);
									}
									catch(IOException ioe) {
									}
									finally {
										nioChan.close();
									}
								}
							}

							@Override
							public boolean isOpen() {
								return !closed;
							}

							@Override
							public int read(ByteBuffer dst) throws IOException {
								throw new UnsupportedOperationException();
							}

							@Override
							public int write(ByteBuffer src) throws IOException {
								var r = src.remaining();
								buf.put(src);
								return r;
							}
						};
						if (gzip) {
							// bufchan = new GZIPChannel(client, bufchan, StandardOpenOption.WRITE);
							bufchan = Channels
									.newChannel(new GZIPOutputStream(Channels.newOutputStream(bufchan), true));
						}
						return bufchan;
					} else {
						calcChunkingAndClose(tx);
						respondWithHeaders(tx);
						return nioChan;
					}
				} else {
					calcChunkingAndClose(tx);
					respondWithHeaders(tx);
					var chan = nioChan;
					if (chunk) {
						chan = new ChunkedChannel(client, (ByteChannel) chan, StandardOpenOption.WRITE);
					}
					if (gzip) {
						chan = Channels.newChannel(new GZIPOutputStream(Channels.newOutputStream(chan), true));
//						chan = new GZIPChannel(client, chan, StandardOpenOption.WRITE);
					}
					return chan;
				}
			} else {
				return responseWriter;
			}

		}

		@Override
		public void transact() throws IOException {
			reset();

			if (LOG.isLoggable(Level.DEBUG))
				LOG.log(Level.DEBUG, "Awaiting HTTP start");

			var line = readLine();
			if (line.length() == 0)
				throw new EOFException();
			if (LOG.isLoggable(Level.DEBUG))
				LOG.log(Level.DEBUG, "HTTP IN: {0}", line);

			var tkns = new StringTokenizer(line);
			var firstToken = tkns.nextToken();
			var method = Method.GET;
			var proto = Protocol.HTTP_0;
			String uri;
			if (tkns.hasMoreTokens()) {
				method = Method.valueOf(firstToken);
				uri = tkns.nextToken();
				proto = Protocol.valueOf(tkns.nextToken().replace('/', '_').replace('.', '_'));

				if (Protocol.HTTP_1_1.compareTo(proto) < 0) {
					throw new UnsupportedOperationException(
							String.format("Only currently supports up to %s", Protocol.HTTP_1_1));
				}
			} else {
				uri = firstToken;
			}
			var tx = new Transaction(uri, method, proto, client, writer(), delegate);
			Transaction.current.set(tx);
			try {
				try {

					/* Read headers up to content */
					while ((line = readLine()) != null && !line.equals("")) {
						if (LOG.isLoggable(Level.TRACE))
							LOG.log(Level.TRACE, "HTTP IN: {0}", line);
						var nvp = Named.parseHeader(line);
						tx.incomingHeaders.put(nvp.name, nvp);
					}

					close = !client.rootContext.keepAlive || Protocol.HTTP_1_1.compareTo(proto) > 0
							|| tx.headersOr(HDR_CONNECTION).orElse(Named.EMPTY).expand(",").containsIgnoreCase("close");

					if (proto.compareTo(Protocol.HTTP_1_0) > 0) {
						tx.headerOr(HDR_HOST).orElseThrow();
					}

					tx.headersOr(HDR_COOKIE).ifPresent(c -> {
						for (var val : c.values()) {
							var bldr = new CookieBuilder();
							var spec = Named.parseSeparatedStrings(val);
							var map = new LinkedHashMap<String, String>();
							for (var el : spec.values()) {
								if(el.name().equalsIgnoreCase("path")) {
									bldr.withPath(el.asString());
								}
								else if(el.name().equalsIgnoreCase("domain")) {
									bldr.withDomain(el.asString());
								}
								else if(el.name().equalsIgnoreCase("httponly")) {
									bldr.withHttpOnly();
								}
								else if(el.name().equalsIgnoreCase("secure")) {
									bldr.withSecure();
								}
								else if(el.name().equalsIgnoreCase("expires")) {
									bldr.withExpires(parseDate(el.asString()));
								}
								else if(el.name().equalsIgnoreCase("max-age")) {
									bldr.withMaxAge(el.asLong());
								}
								else if(el.name().equalsIgnoreCase("samesite")) {
									bldr.withSameSite(SameSite.valueOf(el.asString().toUpperCase()));
								}
								else {
									map.put(el.name(), el.hasValue() ? el.asString() : "");
								}
							}
							for(var en : map.entrySet()) {
								bldr.withName(en.getKey());
								bldr.withValue(en.getValue());
								var cookie = bldr.build();
								tx.incomingCookies.put(cookie.name(), cookie);
							}
						}
					});

					/* Now pass on to user code via the context */
					client.rootContext.get(tx);

				} catch (Exception e) {
					LOG.log(Level.ERROR, "Failed HTTP transaction.", e);
					tx.error(e);
				}

				/*
				 * Make sure all request content is read (user code might not have read any
				 * parts)
				 */
				for (var part : tx.request().asParts()) {
					if (!part.satisfied()) {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "HTTP IN: Reading unsatisifed part {0}", part);
						part.satisfy();
					}
				}

				
				client.rootContext.handleStatus(tx);

				if (tx.responseChannel == null) {
					responseContent(tx);
				}

				writer().flush();
				if (close)
					throw new EOFException();

				if (LOG.isLoggable(Level.DEBUG))
					LOG.log(Level.DEBUG, "Exited transaction normally, setting socket timeout to {0}s",
							client.rootContext.keepAliveTimeoutSecs);
				
				client.timeout(client.rootContext.keepAliveTimeoutSecs * 1000);
			} finally {
				if (tx.content != null)
					tx.content.close();
				
				client.rootContext.logger.ifPresent(l->l.accept(tx));
				
				Transaction.current.set(null);
			}
		}

		private void calcChunkingAndClose(Transaction tx) {
			if (!useLength) {
				if (tx.headerOr(HDR_UPGRADE).isEmpty() && tx.protocol.compareTo(Protocol.HTTP_1_0) > 0 && tx.protocol.compareTo(Protocol.HTTP_2) < 0) {
					chunk = true;
				} else if(!tx.hasResponseHeader(HDR_UPGRADE)) { 
					close = true;
				}
			}
		}

		private void calcResponseLengthAndType(Transaction tx) {
			chunk = false;
			haveLength = useLength = tx.responseLength.isPresent();
			responseLength = useLength ? tx.responseLength.get() : -1;
			responseBigEnoughToCompress = (!useLength || (responseLength >= client.rootContext.minGzipSize));

			// TODO gzip header might contain parameters for compression
			gzip = responseBigEnoughToCompress && client.rootContext.gzip && tx.hasResponse()
					&& tx.outgoingHeaders.containsKey(HDR_CONTENT_ENCODING)
					&& tx.outgoingHeaders.get(HDR_CONTENT_ENCODING).containsIgnoreCase("gzip");

			if (responseBigEnoughToCompress && client.rootContext.gzip
					&& !tx.outgoingHeaders.containsKey(HDR_CONTENT_ENCODING) && tx.hasResponse()) {
				var ae = tx.headersOr(HDR_ACCEPT_ENCODING);
				if (ae.isPresent() && ae.get().expand(",").containsIgnoreCase("gzip")) {
					gzip = true;
					useLength = false; 
				}
			}
		}

		private void reset() {
			close = true;
			chunk = false;
			gzip = false;
			responseWriter = null;
			useLength = false;
			haveLength = false;
			responseLength = -1;
		}

		private void respondWithHeaders(Transaction tx) throws IOException {

			var status = tx.code.orElse(Status.OK);

// HTTP/1.1 says even errors keep the connection alive
//			if (status.getCode() >= 300)
//				close = true;

			var w = writer();
			w.print(tx.protocol().text());
			w.print(" ");
			w.print(status.code);
			w.print(" ");
			w.print(tx.responseText.orElse(status.getText()));
			w.println();

			if (LOG.isLoggable(Level.DEBUG) && !LOG.isLoggable(Level.TRACE))
				LOG.log(Level.DEBUG, "HTTP OUT: {0} {1} {2}", tx.protocol().text(), status.code,
						tx.responseText.orElse(status.getText()));

			if (responseBigEnoughToCompress && client.rootContext.gzip
					&& !tx.outgoingHeaders.containsKey(HDR_CONTENT_ENCODING) && tx.hasResponse()) {
				var ae = tx.headersOr(HDR_ACCEPT_ENCODING);
				if (ae.isPresent() && ae.get().expand(",").containsIgnoreCase("gzip")) {
					w.print(HDR_CONTENT_ENCODING);
					w.println(": gzip");
				}
			}

			if (useLength) {
				w.print(HDR_CONTENT_LENGTH);
				w.print(": ");
				w.print(responseLength);
				w.println();
			}

			if (chunk) {
				w.print(HDR_TRANSFER_ENCODING);
				w.println(": chunked");
				chunk = true;
			}

			/*
			 * else { close = true; }
			 */

			if (!tx.hasResponseHeader(HDR_CONNECTION)) {
				if (close && tx.protocol.compareTo(Protocol.HTTP_2) < 0) {
					w.print(HDR_CONNECTION);
					w.println(": close");
				} else if (tx.protocol.compareTo(Protocol.HTTP_1_0) > 0 && tx.protocol.compareTo(Protocol.HTTP_2) < 0) {
					w.print(HDR_CONNECTION);
					w.println(": keep-alive");
				}
			}

			if (tx.responseType.isPresent()) {
				w.print(HDR_CONTENT_TYPE);
				w.print(": ");
				w.print(tx.responseType.get());
				w.println();
			}

			for (var nvp : tx.outgoingHeaders.values()) {
				w.print(nvp.name());
				w.print(": ");
				w.print(nvp.ofString().orElse(""));
				w.println();
			}

			for (var cookie : tx.outgoingCookies.values()) {
				w.print(HDR_SET_COOKIE);
				w.print(": ");
				w.print(cookie);
				w.println();
			}

			if (!client.rootContext.cache) {
				w.print(HDR_CACHE_CONTROL);
				w.println(": no-cache");
			}

			w.println();
			w.flush();
		}

		private void responseContent(Transaction tx) throws IOException {
			var wout = responseWriter(tx);
			try (var out = wout) {
				if (tx.responder.isPresent()) {
					var buffer = ByteBuffer.allocateDirect(client.rootContext.sendBufferSize);
					try {
						do {
							buffer.clear();
							tx.responder.get().supply(buffer);
							if (buffer.position() > 0) {
								buffer.flip();
								out.write(buffer);
							}
						} while (buffer.position() > 0);
					} finally {
						tx.responder.get().close();
					}
				}
			}
		}

	}

	private static final class HTTPContent implements Content {

		private final Transaction tx;
		private final ReadableByteChannel input;

		private boolean asNamedParts;
		private boolean asParts;
		private boolean asStream;
		private boolean asChannel;
		private List<Part> parts;
		private Iterator<Part> partIterator;

		private HTTPContent(Transaction tx, ReadableByteChannel input) {
			this.tx = tx;
			this.input = input;
		}

		@Override
		public ReadableByteChannel asChannel() {
			if (asParts || asNamedParts || asStream)
				throw new IllegalStateException("Already have content as named or iterated parts.");
			asChannel = true;
			return channelImpl();
		}

		@Override
		public <P extends Part> Iterable<P> asParts(Class<P> partType) {
			if (asStream || asNamedParts || asChannel) {
				return Collections.emptyList();
			}
			asParts = true;
			return asPartsImpl(partType);
		}

		@Override
		public InputStream asStream() {
			if (asParts || asNamedParts || asChannel)
				throw new IllegalStateException("Already have content as named or iterated parts.");
			asStream = true;
			return Channels.newInputStream(channelImpl());
		}

		@Override
		public void close() {
			if (parts != null) {
				parts.forEach(p -> p.close());
			}
		}

		@Override
		public Optional<String> contentType() {
			return tx.headerOr(HDR_CONTENT_TYPE);
		}

		@Override
		public <P extends Part> Optional<P> ofPart(String name, Class<P> clazz) {
			if (asStream || asParts) {
				throw new IllegalStateException("Already have content as stream or iterated parts.");
			}

			if (LOG.isLoggable(Level.TRACE))
				LOG.log(Level.TRACE, "Looking for part named {0} of type {1}", name, clazz);

			for (var part : asPartsImpl(clazz)) {
				if (part.name().equals(name)) {
					if (LOG.isLoggable(Level.TRACE))
						LOG.log(Level.TRACE, "Found part named {0} of type {1}", name, clazz);
					
					return Optional.of(part);
				}
			}

			if (LOG.isLoggable(Level.TRACE))
				LOG.log(Level.TRACE, "Did not find part named {0} of type {1}", name, clazz);

			return Optional.empty();
		}

		@Override
		public Optional<Long> size() {
			return tx.headersOr(HDR_CONTENT_LENGTH).map(o -> o.asLong());
		}

		@SuppressWarnings("unchecked")
		<P extends Part> Iterable<P> asPartsImpl(Class<P> partType) {
			if (parts == null) {
				/* If we have not started iterating yet */
				parts = new ArrayList<>();
				return createIterable(partType);
			} else if (partIterator == null) {
				/* If we have finished iterating */
				return (Iterable<P>) parts;
			} else {
				/* We are part way through iterating */
				return new Iterable<>() {
					@Override
					public Iterator<P> iterator() {
						/* In this state, if we get to the end of the streamed parts then iterate through
						 * the stored parts too
						 */
						return new Iterator<P>() {
							
							P item = null;
							Iterator<P> storedIt;

							@Override
							public boolean hasNext() {
								checkNext();
								return item != null;
							}

							@Override
							public P next() {
								try {
									checkNext();
									if(item == null)
										throw new NoSuchElementException();
									return item;
								}
								finally {
									item = null;
								}
							}
							
							private void checkNext() {
								if(item == null) {
									while(true) {
										if(storedIt == null) {
											if(partIterator.hasNext()) {
												item = (P)partIterator.next();
												break;
											}
											else {
												storedIt = (Iterator<P>) parts.iterator();
											}
										}
										else {
											if(storedIt.hasNext()) {
												item = storedIt.next();
											}
											break;
										}
									}
								}
							}
						};
					}
				};
			}
		}

		<P extends Part> Iterable<P> createIterable(Class<P> partType) {
			return new Iterable<>() {

				@SuppressWarnings("unchecked")
				@Override
				public Iterator<P> iterator() {
					var it = iteratorImpl(new PsuedoCloseByteChannel() {
						@Override
						protected int readImpl(ByteBuffer dst) throws IOException {
							return input.read(dst);
						}

					});
					partIterator = (Iterator<Part>) partCapturingIterator(partType, it);
					return (Iterator<P>) partIterator;
				}
			};
		}

		Iterator<Part> iteratorImpl(ByteChannel input) {
			if (contentType().isPresent()) {
				var content = Named.parseSeparatedStrings(contentType().get());
				var type = content.values().iterator().next();
				switch (type.name()) {
				case "multipart/form-data":
					return new MultipartFormDataPartIterator(tx.client, input,
							content.containsKey("boundary") ? content.get("boundary").asString() : null);
				case "application/x-www-form-urlencoded":
					return new URLEncodedFormDataPartIterator(tx.client, input);
				default:
					return new SinglePartIterator(tx.client, input);
				}
			} else {
				return new SinglePartIterator(tx.client, input);
			}
		}

		<P extends Part> Iterator<P> partCapturingIterator(Class<P> partType, Iterator<Part> it) {
			return new Iterator<>() {

				private P item;
				private P previousItem;

				@Override
				public boolean hasNext() {
					checkNext();
					return item != null;
				}

				@Override
				public P next() {
					checkNext();
					if (item == null)
						throw new NoSuchElementException();
					try {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Parsed part. {0}", item.name());
						parts.add(item);
						return item;
					} finally {
						previousItem = item;
						item = null;
					}
				}

				@SuppressWarnings("unchecked")
				private void checkNext() {
					if (item == null) {
						/*
						 * TODO will also need to drain content if no parts are iterated over at all
						 */
						if (previousItem != null && !previousItem.satisfied()) {

							if (LOG.isLoggable(Level.DEBUG))
								LOG.log(Level.DEBUG, "Satisfying previous part.");

							try {
								previousItem.satisfy();
							} catch (IOException e) {
								throw new UncheckedIOException(e);
							} finally {
								previousItem = null;
							}
						}

						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Waiting for next part of type {0}", partType);

						while (it.hasNext()) {
							Part i = it.next();
							if (partType.isAssignableFrom(i.getClass())) {
								item = (P) i;
								break;
							}
						}

						// After this point, take parts from the gathered list
						if (item == null)
							partIterator = null;
						else  {
							if (LOG.isLoggable(Level.DEBUG))
								LOG.log(Level.DEBUG, "Found part");
						}
					}
				}
			};
		}

		private ReadableByteChannel channelImpl() {
			return new PsuedoCloseByteChannel() {
				@Override
				protected int readImpl(ByteBuffer dst) throws IOException {
					return input.read(dst);
				}
			};
		}
	}

	private final static class LengthLimitedChannel extends WebChannel {

		private final long length;
		private long read;

		public LengthLimitedChannel(Client client, ByteChannel delegate, long length, OpenOption... options) {
			super(client, delegate, options);
			this.length = length;
		}

		@Override
		public int read(ByteBuffer dst) throws IOException {
			if (read >= length) {
				return -1;
			}
			if (read + dst.remaining() > length) {
//				dst = ByteBuffer.allocate((int)length);

//				dst = dst.slice(0, (int)length);

				var over = (int) ((read + dst.remaining()) - length);
				dst.limit(dst.limit() - over);
			}
			var r = delegate.read(dst);
			if (r == -1)
				return r;
			read += r;
			if (read > length) {
				throw new IllegalStateException("Read more than expected.");
			}
			return r;
		}

	}

	private static final class MultipartBoundaryStream extends InputStream {
		enum State {
			WAIT_BOUNDARY, WAIT_NEWLINE, WAIT_END, END
		}

		static byte[] newlineBytes = "\r\n".getBytes(HTTP_CHARSET_ENCODING);

		static byte[] endBytes = "--".getBytes(HTTP_CHARSET_ENCODING);
		private final InputStream chin;
		private byte[] boundaryBytes;
		private int matchIndex;
		private State state = State.WAIT_BOUNDARY;
		private final MultipartFormDataPartIterator iterator;
		private ByteBuffer backBuffer;

		private ByteBuffer readBuffer;

		private MultipartBoundaryStream(InputStream chin, String boundary, MultipartFormDataPartIterator iterator) {
			this.chin = chin;
			this.iterator = iterator;
			boundaryBytes = ("\r\n--" + boundary).getBytes(HTTP_CHARSET_ENCODING);

			backBuffer = ByteBuffer.allocate(boundaryBytes.length);
		}

		@Override
		public int read() throws IOException {
			if (state == State.END)
				return -1;

			while (true) {

				int r;
				if (readBuffer == null) {
					r = chin.read();
					if (r == -1) {
						state = State.END;
						return r;
					}
				} else {
					if (readBuffer.hasRemaining())
						return readBuffer.get();
					readBuffer = null;
					continue;
				}

				switch (state) {
				case WAIT_NEWLINE:
					if (r == newlineBytes[matchIndex]) {
						matchIndex++;
						if (matchIndex == newlineBytes.length) {
							matchIndex = 0;
							state = State.END;
							return -1;
						}
					} else {
						state = State.WAIT_BOUNDARY;
						matchIndex = 0;
						return r;
					}
					break;
				case WAIT_END:
					if (r == endBytes[matchIndex]) {
						matchIndex++;
						if (matchIndex == endBytes.length) {
							matchIndex = 0;
							iterator.end = true;
							state = State.WAIT_NEWLINE;
						}
					} else {
						if (r == newlineBytes[matchIndex]) {
							matchIndex++;
							if (matchIndex == newlineBytes.length) {
								matchIndex = 0;
								state = State.END;
								return -1;
							}
						} else {
							state = State.WAIT_BOUNDARY;
							matchIndex = 0;
							return r;
						}
					}
					break;
				case WAIT_BOUNDARY:
					if (r == boundaryBytes[matchIndex]) {
						matchIndex++;
						if (matchIndex == boundaryBytes.length) {
							backBuffer.clear();
							state = State.WAIT_END;
							matchIndex = 0;
						} else {
							backBuffer.put((byte) r);
						}
					} else {
						if (backBuffer.position() == 0) {
							matchIndex = 0;
							return r;
						} else {
							backBuffer.flip();
							readBuffer = backBuffer;
						}
					}
					break;
				default:
					throw new IllegalStateException();
				}
			}
		}
	}

	private final static class MultipartFormDataPartIterator extends WebChannel implements Iterator<Part> {

		String boundary;
		StringBuilder buffer = new StringBuilder(256);
//		StringBuilder content;
		String contentDisposition;
		String contentType;
		boolean end;
		boolean pastFirstBoundary;
		FormData next;

		MultipartFormDataPartIterator(Client client, ByteChannel chan, String boundary) {
			super(client, chan, StandardOpenOption.READ);
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
			if (end)
				return;

			if (next == null) {
				char ch;
				buffer.setLength(0);
				try {

					MultipartBoundaryStream content = null;

					var charset = client.charset();
					var chin = Channels.newInputStream(delegate);

					while (!end && (ch = (char) chin.read()) != -1) {
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
							if (line.startsWith("--" + boundary)) {
								// Next part
								end = line.endsWith("--");
								if (end)
									break;
								else {
									if (pastFirstBoundary) {
										break;
									} else {
										pastFirstBoundary = true;
									}
								}
							} else if (line.toLowerCase().startsWith(HDR_CONTENT_TYPE + ": ")) {
								contentType = Named.parseHeader(line).asString();
							} else if (line.toLowerCase().startsWith(HDR_CONTENT_DISPOSITION + ": ")) {
								contentDisposition = Named.parseHeader(line).asString();
							} else if (line.equals("")) {
								// content will start after a NL (CR was terminated the readLine())
								if (chin.read() != 10)
									throw new IOException("Excepted newline.");
								content = new MultipartBoundaryStream(chin, boundary, this);
								break;
							} else {
								throw new IllegalStateException("Protocol violation. '" + line + "'");
							}
							buffer.setLength(0);
						} else {
							buffer.append(ch);
						}
					}
					if (end) {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "Multipart stream ended.");
					} else {
						try {
							next = new FormData(contentType, charset, contentDisposition, content);
						} finally {
							content = null;
							end = false;
						}
					}
				} catch (IOException ioe) {
					throw new UncheckedIOException("I/O error while reading URL encoded form parameters.", ioe);
				}
			}
		}
	}

	private static abstract class PsuedoCloseByteChannel implements ByteChannel {

		private boolean closed;

		@Override
		public final void close() throws IOException {
			closed = true;
		}

		@Override
		public final boolean isOpen() {
			return !closed;
		}

		@Override
		public final int read(ByteBuffer dst) throws IOException {
			if (closed)
				throw new IOException("Closed.");
			return readImpl(dst);
		}

		@Override
		public final int write(ByteBuffer src) throws IOException {
			if (closed)
				throw new IOException("Closed.");
			return writeImpl(src);
		}

		protected int readImpl(ByteBuffer dst) throws IOException {
			throw new UnsupportedOperationException();
		}

		protected int writeImpl(ByteBuffer src) throws IOException {
			throw new UnsupportedOperationException();
		}

	}
	
	public final static class HandlerGroup extends AbstractGroup {
	
		public final static class HandlerGroupBuilder extends AbstractGroupBuilder<HandlerGroupBuilder, HandlerGroup> {
			
			private final List<Handler> handlers = new ArrayList<>();
			
			@Override
			public HandlerGroup build() {
				return new HandlerGroup(this);
			}
			public HandlerGroupBuilder handle(Handler...handlers) {
				return handle(Arrays.asList(handlers));
			}
			
			public HandlerGroupBuilder handle(Collection<Handler> handlers) {
				this.handlers.addAll(handlers);
				return this;
			}
		}
		
		private final Collection<Handler> handlers;
	
		private HandlerGroup(HandlerGroupBuilder builder) {
			super(builder);
			this.handlers = Collections.unmodifiableList(builder.handlers);
		}
	
		@Override
		public void get(Transaction tx) throws Exception {
			handleMultiple(tx, handlers());
		}

		@Override
		protected Collection<Handler> handlers() {
			return handlers;
		}
	
	}

	private final static class RootContextImpl extends AbstractContext implements RootContext {

		private static final long DEFAULT_MIN_GZIP_SIZE = 2048;
		
		private final int backlog;
		private final boolean cache;
		private final Optional<InetAddress> httpAddress;
		private final Optional<Integer> httpPort;
		private final Optional<InetAddress> httpsAddress;
		private final Optional<Integer> httpsPort;
		private final boolean keepAlive;
		private final int keepAliveMax;
		private final int keepAliveTimeoutSecs;
		private final boolean gzip;
		private final int sendBufferSize;
		private final int recvBufferSize;
		private final int maxUnchunkedSize;
		private final long minGzipSize;
		private boolean open = true;
		private final Runner runner;
		private final ServerSocketChannel serverSocketChannel;
		private final ServerSocket sslServerSocket;
		private final String threadName;
		private final boolean daemon;
		private final Set<Client> clients = new CopyOnWriteArraySet<>();

		private Thread otherThread;
		private Thread serverThread;

		private RootContextImpl(RootContextBuilder builder) throws UnknownHostException, IOException {
			super(builder);

			threadName = builder.threadName;
			daemon = builder.daemon;
			maxUnchunkedSize = builder.maxUnchunkedSize;

			httpPort = builder.httpPort;
			httpsPort = builder.httpsPort;
			httpAddress = builder.httpAddress;
			httpsAddress = builder.httpsAddress;
			backlog = builder.backlog;
			cache = builder.cache;
			keepAlive = builder.keepAlive;
			gzip = builder.gzip;
			sendBufferSize = builder.sendBufferSize;
			recvBufferSize = builder.recvBufferSize;
			keepAliveTimeoutSecs = builder.keepAliveTimeoutSecs;
			keepAliveMax = builder.keepAliveMax;
			runner = builder.runner.orElse(threadPoolRunner().build());
			minGzipSize = builder.gzipMinSize.orElse(DEFAULT_MIN_GZIP_SIZE);

			if (httpPort.isPresent()) {
				LOG.log(Level.INFO, "Starting HTTP server on port {0}", httpPort.get());
				serverSocketChannel = ServerSocketChannel.open().setOption(StandardSocketOptions.SO_REUSEADDR, true)
						.bind(new InetSocketAddress(httpAddress.orElse(InetAddress.getByName("127.0.0.1")),
								httpPort.orElse(8080)), backlog);
			} else {
				serverSocketChannel = null;
			}

			if (httpsPort.isPresent()) {
				LOG.log(Level.INFO, "Starting HTTPS server on port {0}", httpsPort.get());

				SSLContext sc = null;
				try {
					KeyStore ks = null;
					KeyManagerFactory kmf = null;

					if (builder.keyStore.isPresent()) {
						LOG.log(Level.INFO, "Using provided keystore");
						ks = builder.keyStore.get();
					} else if (builder.keyStoreFile.isPresent() && Files.exists(builder.keyStoreFile.get())) {
						LOG.log(Level.INFO, "Using keystore {0}", builder.keyStoreFile.get());
						try (var in = Files.newInputStream(builder.keyStoreFile.get())) {
							ks = KeyStore.getInstance(builder.keyStoreType.orElse(KeyStore.getDefaultType()));
							ks.load(in, builder.keyStorePassword.orElse(new char[0]));
						}
					} else {
						var p = Paths.get(System.getProperty("user.home"), ".keystore");
						if (Files.exists(p)) {
							try (var in = Files.newInputStream(p)) {
								ks = KeyStore.getInstance(builder.keyStoreType.orElse(KeyStore.getDefaultType()));
								ks.load(in, builder.keyStorePassword.orElse("changeit".toCharArray()));
								LOG.log(Level.INFO, "Using user default keystore");
							} catch (Exception e) {
								LOG.log(Level.WARNING, "Could not load user keystore at {0}.", p, e);
							}
						}

						if (ks == null) {
							LOG.log(Level.INFO, "Using system default keystore");
							sc = SSLContext.getDefault();
						}
					}

					if (sc == null) {
						kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
						kmf.init(ks,
								builder.keyPassword.orElse(builder.keyStorePassword.orElse("changeit".toCharArray())));
						sc = SSLContext.getInstance("TLS");
						sc.init(kmf.getKeyManagers(), null, null);
					}

				} catch (Exception e) {
					throw new IOException("Failed to configure SSL.", e);
				}
				
				sslServerSocket = sc.getServerSocketFactory().createServerSocket(httpsPort.orElse(8443), backlog, httpsAddress.orElse(InetAddress.getByName("127.0.0.1")));

			} else {
				sslServerSocket = null;
			}

		}

		@Override
		public Optional<Integer> httpPort() {
			try {
				return serverSocketChannel == null ? Optional.empty() :  Optional.of(((InetSocketAddress)serverSocketChannel.getLocalAddress()).getPort());
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}

		@Override
		public Optional<Integer> httpsPort() {
			return sslServerSocket == null ? Optional.empty() : Optional.of(sslServerSocket.getLocalPort());
		}

		@Override
		protected void onClose() {
			if (!open)
				throw new IllegalStateException("Already closed.");
			LOG.log(Level.INFO, "Closing root HTTP context.");
			open = false;
			try {
				try {
					if (serverSocketChannel != null)
						serverSocketChannel.close();
				} finally {
					try {
						if (sslServerSocket != null)
							sslServerSocket.close();
					} finally {
						while(!clients.isEmpty()) {
							try {
								clients.iterator().next().close(); 
							}
							catch(Exception e) {}
						}
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
						runner.close();
					}
				}
			} catch(IOException ioe) {
				throw new UncheckedIOException(ioe);
			}
		}

		@Override
		public void get(Transaction tx) throws Exception {

			var matched = false;
			for (var c : handlers.entrySet()) {
				if (c.getKey().matches(tx)) {
					matched = true;
					tx.selector = Optional.of(c.getKey());
					try {
						c.getValue().get(tx);
					} catch (FileNotFoundException fnfe) {
						if (LOG.isLoggable(Level.DEBUG))
							LOG.log(Level.DEBUG, "File not found. {0}", fnfe.getMessage());
						tx.notFound();
					} catch (Exception ise) {
						LOG.log(Level.ERROR, "Request handling failed.", ise);
						tx.error(ise);
					}

					if (tx.responded() || tx.hasResponse())
						break;
				}
			}

			if(!tx.responded() && !tx.hasResponse()) {
				if(matched) {
					tx.responseCode(Status.OK);
				}
				else {
					tx.notFound();
				}
			}

		}

		@Override
		public void join() throws InterruptedException {
			if (serverThread == null)
				throw new IllegalStateException("Not started.");
			serverThread.join();
		}

		@Override
		public void run() {
			serverThread = Thread.currentThread();

			/* Run, keeping number of thread used to minimum required for configuration */

			if (serverSocketChannel == null) {
				/* HTTPS only */
				runOn(true, sslServerSocket, Scheme.HTTPS, httpsPort.get());
			} else if (sslServerSocket == null) {
				/* HTTP only */
				runOn(false, serverSocketChannel, Scheme.HTTP, httpPort.get());
			} else if (serverSocketChannel != null && sslServerSocket != null) {
				/* Both */
				otherThread = new Thread(threadName + "SSL") {
					@Override
					public void run() {
						runOn(true, sslServerSocket, Scheme.HTTPS, httpsPort.get());
					}
				};
				otherThread.setDaemon(true);
				otherThread.start();
				runOn(false, serverSocketChannel, Scheme.HTTP, httpPort.get());
				try {
					otherThread.join();
				} catch (InterruptedException e) {
				}
			} else
				throw new IllegalStateException();
		}

		@Override
		public void start() {
			if (serverThread == null) {
				serverThread = new Thread(this, threadName);
				serverThread.setDaemon(daemon);
				serverThread.start();
			} else
				throw new IllegalStateException("Already started.");

		}

		private void runOn(boolean secure, ServerSocketChannel so, Scheme scheme, int port) {
			while (open) {
				LOG.log(Level.DEBUG, "Waiting for connection (using channels)");
				try {
					runner.run(new Client(secure, port, scheme, so.accept(), this));
				} catch (AsynchronousCloseException ace) {
					if(open)
						LOG.log(Level.ERROR, "Failed waiting for connection.", ace);
				} catch (Exception e) {
					LOG.log(Level.ERROR, "Failed waiting for connection.", e);
				}
			}
		}

		private void runOn(boolean secure, ServerSocket so, Scheme scheme, int port) {
			while (open) {
				LOG.log(Level.DEBUG, "Waiting for connection (using streams)");
				try {
					runner.run(new Client(secure, port, scheme, so.accept(), this));
				} catch (SocketException ace) {
					if(open)
						LOG.log(Level.ERROR, "Failed waiting for connection.", ace);
				} catch (Exception e) {
					LOG.log(Level.ERROR, "Failed waiting for connection.", e);
				}
			}
		}
	}

	private static final class SinglePartIterator implements Iterator<Part> {
		final ByteChannel input;
		final Client client;

		Part next;
		int parts = 0;

		SinglePartIterator(Client client, ByteChannel input) {
			this.input = input;
			this.client = client;
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
				if (next == null)
					throw new NoSuchElementException();
				return next;
			} finally {
				next = null;
			}
		}

		void checkNext() {
			if (next == null) {
				if (parts == 0) {
					next = new Part() {
						private boolean satisfied;

						@Override
						public ReadableByteChannel asChannel() {
							return new ReadableByteChannel() {

								@Override
								public void close() throws IOException {
									try {
										input.close();
									} finally {
										satisfied = true;
									}
								}

								@Override
								public boolean isOpen() {
									return input.isOpen();
								}

								@Override
								public int read(ByteBuffer dst) throws IOException {
									return input.read(dst);
								}
							};
						}

						@Override
						public Reader asReader() {
							var rdr = Channels.newReader(input, client.charset);
							return new FilterReader(rdr) {
								@Override
								public void close() throws IOException {
									try {
										super.close();
									} finally {
										satisfied = true;
									}
								}
							};
						}

						@Override
						public InputStream asStream() {
							var in = Channels.newInputStream(input);
							return new FilterInputStream(in) {
								@Override
								public void close() throws IOException {
									try {
										super.close();
									} finally {
										satisfied = true;
									}
								}
							};
						}

						@Override
						public String asString() {
							var out = new ByteArrayOutputStream();
							try (var in = asStream()) {
								in.transferTo(out);
							} catch (IOException ioe) {
								throw new UncheckedIOException(ioe);
							}
							return new String(out.toByteArray(), client.charset);
						}

						@Override
						public String name() {
							return "default";
						}

						@Override
						public boolean satisfied() {
							return satisfied;
						}

						@Override
						public void satisfy() throws IOException {
							Part.super.satisfy();
							asStream().transferTo(OutputStream.nullOutputStream());
						}
					};
					parts++;
				}
			}
		}
	}

	private static final class SocketTunnelHandler extends AbstractTunnelHandler {

		@Override
		TunnelWireProtocol create(String host, int port, Client client) throws IOException {
			var sckt = SocketChannel.open(new InetSocketAddress(host, port));
			return new TunnelWireProtocol(Optional.of(client.rootContext.sendBufferSize), sckt::read, sckt::write,
					Optional.of(() -> {
						try {
							sckt.close();
						} catch (IOException e) {
						}
					}), client);
		}

	}

	private final static class ThreadPoolRunner implements Runner {
		private ExecutorService pool;

		ThreadPoolRunner(Optional<Integer> threads) {
			pool = threads.isPresent() ? Executors.newFixedThreadPool(threads.get()) : Executors.newCachedThreadPool();
		}

		@Override
		public void close() {
			pool.shutdown();
		}

		@Override
		public void run(Runnable runnable) {
			pool.execute(runnable);
		}

	}

	private final static class URLEncodedFormDataPartIterator extends WebChannel implements Iterator<Part> {

		StringBuilder buffer = new StringBuilder(256);
		Part next;

		URLEncodedFormDataPartIterator(Client client, ByteChannel input) {
			super(client, input, StandardOpenOption.READ);
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
				int r;
				buffer.setLength(0);

				try {
					while ((r= readASCIIChar()) != -1) {
						ch = (char)r;
						if (ch == '&') {
							// Next parameter
							break;
						} else
							buffer.append(ch);
					}
					if (buffer.length() > 0)
						next = Named.parseParameter(buffer.toString());
				} catch (IOException ioe) {
					throw new IllegalStateException("I/O error while reading URL encoded form parameters.");
				}
			}
		}
	}

	private final static class URLResource implements Handler {

		private URL url;

		private URLResource(URL url) {
			this.url = url;
		}

		@Override
		public void get(Transaction req) throws Exception {
			LOG.log(Level.DEBUG, "Resource @{0}", url);
			var conx = url.openConnection();
			var lastMod = new Date( ((conx.getLastModified() + 500) / 1000) * 1000 );
			if(req.headerOr(HDR_IF_MODIFIED_SINCE).isPresent()) {
				var date = parseDate(req.header(HDR_IF_MODIFIED_SINCE));
				if(lastMod.after(date)) {
					req.responseCode(Status.NOT_MODIFIED);
					return;
				}
			}
			req.responseLength(conx.getContentLengthLong());
			req.responseType(bestMimeType(urlToFilename(url), conx.getContentType()));
			req.header(HDR_LAST_MODIFIED, formatDate(lastMod));
			
			req.response(url.openStream());
		}

	}
	
	private static abstract class WebChannel implements ByteChannel {

		protected final Client client;
		protected final ByteChannel delegate;
		protected final List<OpenOption> options;

		protected PrintWriter writer;
		protected ByteBuffer readBuffer;
		protected StringBuilder stringBuffer;

		WebChannel(Client client, ByteChannel delegate, OpenOption... options) {
			this.client = client;
			this.delegate = delegate;
			for (var o : options) {
				if (o != StandardOpenOption.READ && o != StandardOpenOption.WRITE) {
					throw new IllegalArgumentException(MessageFormat.format("OpenOption may only be either {0} or {1}",
							StandardOpenOption.READ, StandardOpenOption.WRITE));
				}
			}
			this.options = Arrays.asList(options);

			readBuffer = ByteBuffer.allocate(1);
			stringBuffer = new StringBuilder(256);
		}

		@Override
		public void close() throws IOException {
			delegate.close();
		}

		@Override
		public boolean isOpen() {
			return delegate.isOpen();
		}

		@Override
		public int read(ByteBuffer dst) throws IOException {
			return delegate.read(dst);
		}

		public int readASCIIChar() throws IOException {
			readBuffer.clear();
			var r = delegate.read(readBuffer);
			if (r == -1)
				return -1;
			return Byte.toUnsignedInt(readBuffer.get(0));
		}

		public String readLine() throws IOException {
			try {
				char ch;
				int r;
				boolean cr = false;
				while ((r = readASCIIChar()) != -1) {
					ch = (char)r;
					if (ch == '\r') {
						if (cr) {
							stringBuffer.append("\r");
						} 
						cr = true;
					} else if (ch == '\n' && cr) {
						break;
					} else {
						stringBuffer.append(ch);
					}
				}
				return stringBuffer.toString();
			} finally {
				stringBuffer.setLength(0);
			}
		}

		@Override
		public int write(ByteBuffer src) throws IOException {
			return delegate.write(src);
		}

		PrintWriter writer() throws IOException {
			if (writer == null) {

				if (options.contains(StandardOpenOption.WRITE))
					writer = new PrintWriter(Channels.newWriter(delegate, HTTP_CHARSET_ENCODING)) {
						@Override
						public void println() {
							print("\r\n");
						}

						@Override
						public void write(String s) {
							if (LOG.isLoggable(Level.DEBUG)) {
								LOG.log(Level.DEBUG, "OUT: " + s.replace("\r", "<cr>").replace("\n", "<nl>"));
							}
							super.write(s);
						}
					};
				else
					throw new IllegalStateException("Channel is not for writing.");

			}
			return writer;
		}
	}

	static final int DEFAULT_BUFFER_SIZE = 32768;
	public static final String DEFAULT_SESSION_COOKIE_NAME= "uHTTPD_SESSION";
	public static final Charset HTTP_CHARSET_ENCODING;

	static {
		HTTP_CHARSET_ENCODING = Charset.forName("ISO-8859-1");
	}

	public static final String HDR_CACHE_CONTROL = "cache-control";
	public static final String HDR_ACCEPT_ENCODING = "accept-encoding";
	public static final String HDR_CONTENT_ENCODING = "content-encoding";
	public static final String HDR_CONNECTION = "connection";
	public static final String HDR_CONTENT_DISPOSITION = "content-disposition";
	public static final String HDR_CONTENT_LENGTH = "content-length";
	public static final String HDR_TRANSFER_ENCODING = "transfer-encoding";
	public static final String HDR_LAST_MODIFIED = "last-modified";
	public static final String HDR_IF_MODIFIED_SINCE = "if-modified-since";
	public static final String HDR_IF_UNMODIFIED_SINCE = "if-unmodified-since";
	public static final String HDR_CONTENT_TYPE = "content-type";
	public static final String HDR_HOST = "host";
	public static final String HDR_UPGRADE = "upgrade";
	public static final String HDR_SET_COOKIE = "set-cookie";
	public static final String HDR_COOKIE = "cookie";
	public static final String HDR_X_FORWARDED_HOST = "x-forwarded-host";
	public static final String HDR_X_FORWARDED_FOR = "x-forwarded-for";
	public static final String HDR_USER_AGENT = "user-agent";
	public static final String HDR_REFERER = "referer";

	final static Logger LOG = System.getLogger("UHTTPD");

	private final static HandlerSelector ALL_SELECTOR = new AllSelector();

	private static final String WEBSOCKET_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	/**
	 * Date format pattern used to parse HTTP date headers in RFC 1123 format.
	 */
	public static final String PATTERN_RFC1123 = "EEE, dd MMM yyyy HH:mm:ss zzz";

	/**
	 * Simple date format for the creation date ISO representation (partial).
	 */
	protected static final String PATTERN_ISO = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/**
	 * Date format pattern used to parse HTTP date headers in RFC 1036 format.
	 */
	public static final String PATTERN_RFC1036 = "EEE, dd-MMM-yy HH:mm:ss zzz";

	/**
	 * Date format pattern used to parse HTTP date headers in ANSI C
	 * {@code asctime()} format.
	 */
	public static final String PATTERN_ASCTIME = "EEE MMM d HH:mm:ss yyyy";

	private static final String[] DEFAULT_PATTERNS = new String[] { PATTERN_RFC1123, PATTERN_RFC1036, PATTERN_ASCTIME };

	private static final Date DEFAULT_TWO_DIGIT_YEAR_START;

	public static final TimeZone GMT = TimeZone.getTimeZone("GMT");

	static {
		final Calendar calendar = Calendar.getInstance();
		calendar.setTimeZone(GMT);
		calendar.set(2000, Calendar.JANUARY, 1, 0, 0, 0);
		calendar.set(Calendar.MILLISECOND, 0);
		DEFAULT_TWO_DIGIT_YEAR_START = calendar.getTime();
	}

	public static Handler classpathResource(Class<?> clazz, String path) {
		return new ClasspathResource(Optional.empty(), Optional.of(clazz), path);
	}
	
	public static Handler classpathResource(ClassLoader classLoader, String path) {
		return classpathResource(Optional.of(classLoader), path);
	}

	public static Handler classpathResource(Optional<ClassLoader> classLoader, String path) {
		return new ClasspathResource(classLoader, Optional.empty(), path);
	}

	public static Handler classpathResource(String path) {
		return classpathResource(Optional.empty(), path);
	}

	public static Handler classpathResources(String regexpPatternWithGroups, Optional<ClassLoader> classLoader,
			String prefix) {
		return new ClasspathResources(regexpPatternWithGroups, classLoader, prefix);
	}

	public static ContextBuilder context(String path) {
		return new ContextBuilder(path);
	}

	public static CookieBuilder cookie(String name, String value) {
		return new CookieBuilder().withName(name).withValue(value);
	}

	public static Handler fileResource(Path path) {
		return new FileResource(path);
	}

	public static Handler fileResources(String regexpPatternWithGroups, Path root) {
		return new FileResources(regexpPatternWithGroups, root);
	}

	//
	// The following code comes from Apache Http client DateUtils under
	// the same license as this project.
	//

	public static String formatDate(Date date) {
		return DateFormatHolder.formatFor(PATTERN_RFC1123).format(date);
	}

	public static String formatInstant(Instant instant) {
		return formatDate(new Date(instant.toEpochMilli()));
	}

	public static String formatISODate(Date date) {
		return DateFormatHolder.formatFor(PATTERN_ISO).format(date);
	}

	public static String formatISOInstant(Instant instant) {
		return formatISODate(new Date(instant.toEpochMilli()));
	}

	public static HttpBasicAuthenticationBuilder httpBasicAuthentication(
			Authenticator<UsernameAndPassword> authenticator) {
		return new HttpBasicAuthenticationBuilder(authenticator);
	}

	public static SessionCookiesBuilder sessionCookies() {
		return new SessionCookiesBuilder();
	}

	public static String bestMimeType(String fileName, String detectedType) {
		if(detectedType == null || detectedType.isEmpty() || detectedType.equalsIgnoreCase("content/unknown")) {
			return URLConnection.guessContentTypeFromName(fileName);
		}
		return detectedType;
	}

	public static String mimeType(URL url) {
		try {
			URLConnection conx = url.openConnection();
			try {
				return bestMimeType(urlToFilename(url), conx.getContentType());
			} finally {
				try {
					conx.getInputStream().close();
				} catch (IOException ioe) {
				}
			}
		} catch (IOException ioe) {
			return bestMimeType(urlToFilename(url), null);
		}
	}

	public static String urlToFilename(URL url) {
		return Paths.get(url.getPath()).getFileName().toString();
	}

	public static RootContextBuilder server() {
		return new RootContextBuilder();
	}

	public static TunnelHandler socketTunnel() {
		return new SocketTunnelHandler();
	}

	public static ThreadPoolRunnerBuilder threadPoolRunner() {
		return new ThreadPoolRunnerBuilder();
	}

	public static TunnelBuilder tunnel() {
		return new TunnelBuilder();
	}

	public static Handler urlResource(URL url) {
		return new URLResource(url);
	}

	/**
	 * Parses the date value using the given date formats.
	 *
	 * @param dateValue the date value to parse
	 *
	 * @return the parsed date or null if input could not be parsed
	 */
	static Date parseDate(final String dateValue) {
		return parseDate(dateValue, DEFAULT_PATTERNS, null);
	}

	/**
	 * Parses the date value using the given date formats.
	 *
	 * @param dateValue   the date value to parse
	 * @param dateFormats the date formats to use
	 * @param startDate   During parsing, two digit years will be placed in the
	 *                    range {@code startDate} to {@code startDate + 100 years}.
	 *                    This value may be {@code null}. When {@code null} is given
	 *                    as a parameter, year {@code 2000} will be used.
	 *
	 * @return the parsed date or null if input could not be parsed
	 */
	static Date parseDate(final String dateValue, final String[] dateFormats, final Date startDate) {
		final String[] localDateFormats = dateFormats != null ? dateFormats : DEFAULT_PATTERNS;
		final Date localStartDate = startDate != null ? startDate : DEFAULT_TWO_DIGIT_YEAR_START;
		String v = dateValue;
		// trim single quotes around date if present
		// see issue #5279
		if (v.length() > 1 && v.startsWith("'") && v.endsWith("'")) {
			v = v.substring(1, v.length() - 1);
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
	}

}