package com.sshtools.uhttpd;

import com.sshtools.uhttpd.UHTTPD.RootContextBuilder;

public class UHTTPDSSLTest extends UHTTPDTest {

	@Override
	protected RootContextBuilder createServer() {
		return UHTTPD.server().withoutHttp().withHttps(58443);
	}

	@Override
	protected String clientURL() {
		return "https://localhost:58443";
	}
	

}
