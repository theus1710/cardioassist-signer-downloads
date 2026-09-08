package br.com.cardioassist.signer;
import java.security.*; import java.security.cert.X509Certificate;
record CertificateChoice(KeyStore store, String alias, PrivateKey key, X509Certificate certificate, X509Certificate[] chain) {
  String summary() { return certificate.getSubjectX500Principal()+"\nIssuer: "+certificate.getIssuerX500Principal()+"\nValid: "+certificate.getNotBefore()+" to "+certificate.getNotAfter(); }
}