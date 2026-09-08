package br.com.cardioassist.signer;

import org.bouncycastle.asn1.*; import org.bouncycastle.asn1.x500.X500Name; import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder; import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder; import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder; import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import java.math.BigInteger; import java.security.*; import java.util.Date; import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

class CertificateCpfTest {
 @Test void readsIcpBrasilCpfAndRejectsMismatch() throws Exception {
   var cert=certificateWithCpfSan("12345678909");
   assertEquals("12345678909",ValidationCli.cpfFromSan(cert));
   assertNotEquals("99999999999",ValidationCli.cpfFromSan(cert));
 }
 @Test void readsCpfFromCompositeIcpBrasilSan() throws Exception {
   assertEquals("12345678909",ValidationCli.cpfFromSan(certificateWithCpfSan("0101199012345678909IDENTITY-FIELDS")));
 }
 @Test void rejectsCpfWithInvalidChecksum() throws Exception {
   assertNull(ValidationCli.cpfFromSan(certificateWithCpfSan("0101199012345678900IDENTITY-FIELDS")));
   assertFalse(ValidationCli.validCpf("12345678900"));
   assertThrows(SecurityException.class,()->ValidationCli.normalizeCpf("123.456.789-00"));
 }
 @Test void loadsOnlyFourPinnedOfficialRootsAndNotAnAttackerRoot() throws Exception {
   var roots=ValidationCli.loadTrustAnchors();
   assertEquals(4,roots.size());
   var attacker=certificateWithCpfSan("12345678909");
   assertTrue(roots.stream().noneMatch(a->a.getTrustedCert().equals(attacker)));
   var suppliedByCms=new CollectionStore<X509CertificateHolder>(java.util.List.of(new JcaX509CertificateHolder(attacker)));
   assertThrows(GeneralSecurityException.class,()->ValidationCli.validateChain(attacker,suppliedByCms));
 }
 @Test void customUriRequiresCorrectForm() {
   UriRequest.LaunchRequest request=UriRequest.parse("cardioassist-signer://sign?session=42&launch=abc&pairing=def");
   assertEquals("42",request.session());
   assertThrows(IllegalArgumentException.class,()->UriRequest.parse("https://example/sign?session=42&launch=abc&pairing=def"));
 }
 @Test void rejectsSignedFileWhoseOriginalPrefixWasTampered() throws Exception {
   var unsigned=Files.createTempFile("unsigned-", ".pdf"); var signed=Files.createTempFile("signed-", ".pdf");
   try {
     Files.write(unsigned,new byte[]{1,2,3,4});
     Files.write(signed,new byte[]{1,9,3,4,5});
     assertThrows(SecurityException.class,()->ValidationCli.verify(unsigned,signed,"12345678909"));
   } finally { Files.deleteIfExists(unsigned); Files.deleteIfExists(signed); }
 }
 @Test void rejectsUnsignedBytesAfterByteRangeAndMalformedOrOversizedGaps() {
   byte[] appended="x<00>TAILjunk".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
   assertThrows(SecurityException.class,()->ValidationCli.validateByteRange(appended,new int[]{0,1,5,4}));
   byte[] multiple="x<00><00>x".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
   assertThrows(SecurityException.class,()->ValidationCli.validateByteRange(multiple,new int[]{0,1,9,1}));
   byte[] oversized=new byte[131077];oversized[1]='<';oversized[131075]='>';
   assertThrows(SecurityException.class,()->ValidationCli.validateByteRange(oversized,new int[]{0,1,131076,1}));
 }
 private static java.security.cert.X509Certificate certificateWithCpfSan(String value) throws Exception {
   KeyPair kp=KeyPairGenerator.getInstance("RSA").generateKeyPair(); X500Name n=new X500Name("CN=test");
   var b=new JcaX509v3CertificateBuilder(n,BigInteger.valueOf(System.nanoTime()),new Date(System.currentTimeMillis()-1000),new Date(System.currentTimeMillis()+60000),n,kp.getPublic());
   ASN1Encodable other=new DERSequence(new ASN1Encodable[]{new ASN1ObjectIdentifier("2.16.76.1.3.1"),new DERTaggedObject(true,0,new DERUTF8String(value))});
   b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.otherName,other)));
   X509CertificateHolder h=b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
   return new JcaX509CertificateConverter().getCertificate(h);
 }
}