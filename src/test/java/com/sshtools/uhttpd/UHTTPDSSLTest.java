package com.sshtools.uhttpd;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.junit.jupiter.api.BeforeAll;

import com.github.mizosoft.methanol.Methanol.Builder;
import com.sshtools.uhttpd.UHTTPD.RootContextBuilder;

public class UHTTPDSSLTest extends UHTTPDTest {

    @BeforeAll
    public static void beforeClass()
    {
		
	}
    
	@Override
	protected RootContextBuilder createServer() {
		try {
			var ks = KeyStore.getInstance("JKS");
			try(var in = UHTTPDSSLTest.class.getResourceAsStream("/uhttpd.keystore")) {
				ks.load(in, "changeit".toCharArray());
			}
			return UHTTPD.server().withoutHttp().withHttps(58443).withKeyStore(ks);
		}
		catch(KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException kse) {
			throw new IllegalStateException("Failed to setup keystore.", kse);
		}
	}

	@Override	
	protected void configureClient(Builder builder) {
		try {
			var sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, new TrustManager[] { new DumbTrustManager() }, new java.security.SecureRandom());
			var sslParameters = sslContext.getDefaultSSLParameters();
			sslParameters.setEndpointIdentificationAlgorithm(null);
			builder.sslParameters(sslParameters);
			builder.sslContext(sslContext);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Could not initialise SSL.", e);
		}
	}

	@Override
	protected String clientURL() {
		return "https://localhost:58443";
	}
	
	static class DumbTrustManager extends X509ExtendedTrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
		}
		
	}

}
