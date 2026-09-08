package br.com.cardioassist.signer;
import java.security.*; import java.security.cert.X509Certificate; import java.util.*;
final class CertificateStores {
 static List<CertificateChoice> system() throws Exception {
   String os=System.getProperty("os.name","").toLowerCase(Locale.ROOT);
   String type=os.contains("win")?"Windows-MY":os.contains("mac")?"KeychainStore":null;
   if(type==null) return List.of();
   KeyStore ks=KeyStore.getInstance(type); ks.load(null,null); List<CertificateChoice> out=new ArrayList<>();
   for(Enumeration<String> e=ks.aliases();e.hasMoreElements();) {String a=e.nextElement();
     if(ks.isKeyEntry(a)&&ks.getCertificate(a) instanceof X509Certificate c) out.add(new CertificateChoice(ks,a,null,c,chain(ks,a)));
   } return out;
 }
 static CertificateChoice pfx(java.nio.file.Path file,char[] pass) throws Exception {
   KeyStore ks=KeyStore.getInstance("PKCS12"); try(var in=java.nio.file.Files.newInputStream(file)){ks.load(in,pass);}
   for(Enumeration<String>e=ks.aliases();e.hasMoreElements();){String a=e.nextElement();if(ks.isKeyEntry(a)&&ks.getCertificate(a) instanceof X509Certificate c)
     return new CertificateChoice(ks,a,(PrivateKey)ks.getKey(a,pass),c,chain(ks,a));}
   throw new GeneralSecurityException("No private-key certificate was found in this PFX/P12");
 }
 static CertificateChoice unlock(CertificateChoice c,char[] pin) throws Exception {return new CertificateChoice(c.store(),c.alias(),(PrivateKey)c.store().getKey(c.alias(),pin),c.certificate(),c.chain());}
 private static X509Certificate[] chain(KeyStore k,String a)throws KeyStoreException {return Arrays.stream(k.getCertificateChain(a)).map(x->(X509Certificate)x).toArray(X509Certificate[]::new);}
}