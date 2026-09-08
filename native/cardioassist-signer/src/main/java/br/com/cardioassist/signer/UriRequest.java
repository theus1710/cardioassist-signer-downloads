package br.com.cardioassist.signer;

import java.net.URI;

final class UriRequest {
  static LaunchRequest parse(String raw) {
    URI u = URI.create(raw);
    if (!"cardioassist-signer".equalsIgnoreCase(u.getScheme()) || !"sign".equalsIgnoreCase(u.getHost()))
      throw new IllegalArgumentException("Expected cardioassist-signer://sign?code=...");
    String q = u.getRawQuery();
    if (q == null) throw new IllegalArgumentException("Pairing code is required");
    String session = value(q, "session"), launch = value(q, "launch"), pairing = value(q, "pairing");
    if (session == null || !session.matches("[1-9][0-9]*") || launch == null || pairing == null)
      throw new IllegalArgumentException("Expected session, launch, and pairing parameters");
    return new LaunchRequest(session, launch, pairing);
  }
  private static String value(String query, String name) {
    for (String p : query.split("&")) if (p.startsWith(name + "=") && p.length() > name.length() + 1)
      return java.net.URLDecoder.decode(p.substring(name.length() + 1), java.nio.charset.StandardCharsets.UTF_8);
    return null;
  }
  record LaunchRequest(String session, String launch, String pairing) {}
}