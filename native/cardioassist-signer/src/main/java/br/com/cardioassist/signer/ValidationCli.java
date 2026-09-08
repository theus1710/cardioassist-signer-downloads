package br.com.cardioassist.signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.*;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.*; import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder; import org.bouncycastle.cms.*; import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import java.io.*; import java.nio.file.*; import java.security.*; import java.security.cert.*; import java.security.interfaces.*; import java.util.*;

/** Fail-closed verifier intended for server invocation, with one JSON result only. */
final class ValidationCli {
 private static final Map<String,String> ICP_BRASIL_ROOTS=Map.of(
   "ICP-Brasilv5.crt","CAA53FC6091C6951887C976E378F6EF89AA6377C55D97B6475422B71ED7E9B17",
   "ICP-Brasilv6.crt","3BDB9B509352F1D3D71C2BF64D9A38A4E6CEBDA27809D77F7AC476CBDE6E314A",
   "ICP-Brasilv7.crt","5657E70580EB678983F3ED7DFCE091D84CAE6549389A47FCCDA8D0E4DC2CF576",
   "ICP-Brasilv12.crt","D8478E37CE19C690CF657381E68FE600E4E1A042536830F06847E03E554C4B01");
 static int run(String[] a) {
   if(a.length!=4){out(false,"USAGE");return 2;}
   try { Metadata metadata=verify(Path.of(a[1]),Path.of(a[2]),normalizeCpf(a[3]));outSuccess(metadata);return 0; }
   catch(Exception e){out(false,errorCode(e));return 1;}
 }
 static Metadata verify(Path unsigned,Path signed,String expectedCpf)throws Exception {
   byte[] original=Files.readAllBytes(unsigned), result=Files.readAllBytes(signed);
   if(result.length<=original.length || !Arrays.equals(original,Arrays.copyOf(result,original.length))) throw new SecurityException("signed file is not an incremental update of supplied original");
   try(PDDocument source=Loader.loadPDF(unsigned.toFile());PDDocument d=Loader.loadPDF(signed.toFile())) {
     if(!source.getSignatureDictionaries().isEmpty())throw new SecurityException("original PDF must be unsigned");
     List<PDSignature> signatures=d.getSignatureDictionaries();
     if(signatures.size()!=1)throw new SecurityException("exactly one PDF signature is required");
     PDSignature sig=signatures.get(signatures.size()-1);
     int[] br=sig.getByteRange();
     validateByteRange(result,br);
     validateSignatureOnlyRevision(source,d,sig);
      return verifyCms(sig.getSignedContent(new ByteArrayInputStream(result)),sig.getContents(new ByteArrayInputStream(result)),expectedCpf);
   }
 }
 static void validateByteRange(byte[] pdf,int[] br) {
   if(br==null||br.length!=4||br[0]!=0||br[1]<1||br[2]<=br[1]||br[3]<1||((long)br[2]+br[3])!=pdf.length)
     throw new SecurityException("invalid PDF ByteRange");
   int gap=br[2]-br[1];
   if(gap<4||gap>131074||pdf[br[1]]!='<'||pdf[br[2]-1]!='>')throw new SecurityException("invalid signature Contents gap");
   int before=br[1]-1;while(before>=0&&isPdfWhitespace(pdf[before]))before--;
   byte[] contentsName="/Contents".getBytes(java.nio.charset.StandardCharsets.US_ASCII);int nameStart=before-contentsName.length+1;
   if(nameStart<0||!Arrays.equals(contentsName,Arrays.copyOfRange(pdf,nameStart,before+1)))
     throw new SecurityException("ByteRange gap is not the signature Contents token");
   int digits=0;
   for(int i=br[1]+1;i<br[2]-1;i++){int c=pdf[i]&255;if(Character.digit(c,16)<0)throw new SecurityException("signature Contents gap is not hex");digits++;}
   if((digits&1)!=0)throw new SecurityException("invalid signature Contents padding");
 }
 private static boolean isPdfWhitespace(byte value){int c=value&255;return c==0||c==9||c==10||c==12||c==13||c==32;}
 static void validateSignatureOnlyRevision(PDDocument source,PDDocument signed,PDSignature signature)throws Exception {
   rejectActiveContent(source.getDocumentCatalog().getCOSObject(),new IdentityHashMap<>());
   rejectActiveContent(signed.getDocumentCatalog().getCOSObject(),new IdentityHashMap<>());
   COSDictionary originalCatalog=source.getDocumentCatalog().getCOSObject(),signedCatalog=signed.getDocumentCatalog().getCOSObject();
   deepEqual(originalCatalog,signedCatalog,Set.of(COSName.ACRO_FORM,COSName.PAGES),new HashSet<>());
   deepEqual(source.getDocumentInformation().getCOSObject(),signed.getDocumentInformation().getCOSObject(),Set.of(),new HashSet<>());
   if(originalCatalog.containsKey(COSName.ACRO_FORM))throw new SecurityException("pre-existing AcroForm is not accepted");
   COSBase formBase=deref(signedCatalog.getItem(COSName.ACRO_FORM));
   if(!(formBase instanceof COSDictionary formDictionary)||formDictionary.containsKey(COSName.XFA))throw new SecurityException("invalid signature AcroForm");
   requireOnlyKeys(formDictionary,Set.of(COSName.FIELDS,COSName.SIG_FLAGS));
   PDAcroForm form=new PDAcroForm(signed,formDictionary);
   List<PDField> fields=new ArrayList<>();for(PDField f:form.getFieldTree())fields.add(f);
   if(fields.size()!=1||!(fields.get(0) instanceof PDSignatureField field)||field.getSignature()==null
     ||field.getSignature().getCOSObject()!=signature.getCOSObject())throw new SecurityException("unexpected form fields");
   requireOnlyKeys(field.getCOSObject(),Set.of(COSName.FT,COSName.V,COSName.T,COSName.TYPE,COSName.FF,COSName.KIDS,
     COSName.SUBTYPE,COSName.F,COSName.P));
   requireOnlyKeys(signature.getCOSObject(),Set.of(COSName.TYPE,COSName.FILTER,COSName.SUB_FILTER,COSName.CONTENTS,
     COSName.BYTERANGE,COSName.M,COSName.NAME));
   if(source.getNumberOfPages()!=signed.getNumberOfPages())throw new SecurityException("page tree changed");
   if(field.getWidgets().size()!=1)throw new SecurityException("exactly one signature widget is required");
   var signatureWidget=field.getWidgets().get(0);COSDictionary widget=signatureWidget.getCOSObject();
   if(widget.containsKey(COSName.RECT)||widget.containsKey(COSName.AP)||widget.getInt(COSName.F)!=35
     ||!signatureWidget.isInvisible()||!signatureWidget.isHidden()||!signatureWidget.isNoView()||signatureWidget.isPrinted())
     throw new SecurityException("signature widget is not deterministically invisible");
   comparePageTree(source.getDocumentCatalog().getPages().getCOSObject(),signed.getDocumentCatalog().getPages().getCOSObject(),true);
   int widgetOccurrences=0;
   for(int i=0;i<source.getNumberOfPages();i++){
     if(!source.getPage(i).getAnnotations().isEmpty())throw new SecurityException("pre-existing annotations are not accepted");
     deepEqual(source.getPage(i).getCOSObject(),signed.getPage(i).getCOSObject(),Set.of(COSName.PARENT,COSName.ANNOTS),new HashSet<>());
     compareEffectivePageAttributes(source.getPage(i),signed.getPage(i));
     for(var annotation:signed.getPage(i).getAnnotations())if(annotation.getCOSObject()==widget){
       if(deref(widget.getItem(COSName.P))!=signed.getPage(i).getCOSObject())throw new SecurityException("signature widget page binding changed");
       widgetOccurrences++;
     }else throw new SecurityException("unexpected annotation");
   }
   if(widgetOccurrences!=1)throw new SecurityException("signature widget is not bound to exactly one page");
 }
 private static void comparePageTree(COSDictionary original,COSDictionary signed,boolean root)throws IOException {
   if(!COSName.PAGES.equals(original.getCOSName(COSName.TYPE))||!COSName.PAGES.equals(signed.getCOSName(COSName.TYPE)))
     throw new SecurityException("invalid page-tree node");
   deepEqual(original,signed,Set.of(COSName.PARENT,COSName.KIDS),new HashSet<>());
   COSArray a=original.getCOSArray(COSName.KIDS),b=signed.getCOSArray(COSName.KIDS);
   if(a==null||b==null||a.size()!=b.size())throw new SecurityException("page-tree structure changed");
   for(int i=0;i<a.size();i++){
     COSDictionary left=(COSDictionary)deref(a.get(i)),right=(COSDictionary)deref(b.get(i));
     if(deref(left.getItem(COSName.PARENT))!=original||deref(right.getItem(COSName.PARENT))!=signed)
       throw new SecurityException("page parent linkage changed");
     COSName lt=left.getCOSName(COSName.TYPE),rt=right.getCOSName(COSName.TYPE);
     if(!Objects.equals(lt,rt))throw new SecurityException("page-tree node type changed");
     if(COSName.PAGES.equals(lt))comparePageTree(left,right,false);
     else if(COSName.PAGE.equals(lt))deepEqual(left,right,Set.of(COSName.PARENT,COSName.ANNOTS),new HashSet<>());
     else throw new SecurityException("invalid page-tree child");
   }
 }
 private static void compareEffectivePageAttributes(org.apache.pdfbox.pdmodel.PDPage a,org.apache.pdfbox.pdmodel.PDPage b)throws IOException {
   compareBox(a.getMediaBox(),b.getMediaBox());compareBox(a.getCropBox(),b.getCropBox());
   compareBox(a.getBleedBox(),b.getBleedBox());compareBox(a.getTrimBox(),b.getTrimBox());compareBox(a.getArtBox(),b.getArtBox());
   if(a.getRotation()!=b.getRotation())throw new SecurityException("effective page rotation changed");
   COSBase ar=a.getResources()==null?null:a.getResources().getCOSObject(),br=b.getResources()==null?null:b.getResources().getCOSObject();
   deepEqual(ar,br,Set.of(),new HashSet<>());
 }
 private static void compareBox(org.apache.pdfbox.pdmodel.common.PDRectangle a,org.apache.pdfbox.pdmodel.common.PDRectangle b)throws IOException {
   deepEqual(a==null?null:a.getCOSArray(),b==null?null:b.getCOSArray(),Set.of(),new HashSet<>());
 }
 private static void requireOnlyKeys(COSDictionary dictionary,Set<COSName> allowed){
   if(!allowed.containsAll(dictionary.keySet()))throw new SecurityException("unexpected signature-only dictionary entry");
 }
 private static final Set<COSName> ACTIVE_KEYS=Set.of(COSName.getPDFName("JS"),COSName.getPDFName("JavaScript"),
   COSName.getPDFName("AA"),COSName.getPDFName("A"),COSName.getPDFName("OpenAction"),COSName.getPDFName("Launch"),
   COSName.getPDFName("EmbeddedFiles"),COSName.getPDFName("EF"),COSName.getPDFName("XFA"));
 private static void rejectActiveContent(COSBase value,IdentityHashMap<COSBase,Boolean> seen)throws IOException {
   value=deref(value);if(value==null||seen.put(value,Boolean.TRUE)!=null)return;
   if(value instanceof COSDictionary dictionary){for(COSName key:dictionary.keySet()){if(ACTIVE_KEYS.contains(key))throw new SecurityException("active or embedded content is prohibited");rejectActiveContent(dictionary.getItem(key),seen);}}
   else if(value instanceof COSArray array)for(COSBase item:array)rejectActiveContent(item,seen);
 }
 private static void deepEqual(COSBase left,COSBase right,Set<COSName> ignored,Set<BasePair> seen)throws IOException {
   left=deref(left);right=deref(right);if(left==right)return;if(left==null||right==null||left.getClass()!=right.getClass())throw new SecurityException("PDF document graph changed");
   BasePair pair=new BasePair(left,right);if(!seen.add(pair))return;
   if(left instanceof COSStream a){COSStream b=(COSStream)right;compareDictionaries(a,b,ignored,seen);try(InputStream x=a.createRawInputStream();InputStream y=b.createRawInputStream()){if(!Arrays.equals(x.readAllBytes(),y.readAllBytes()))throw new SecurityException("PDF stream changed");}}
   else if(left instanceof COSDictionary a)compareDictionaries(a,(COSDictionary)right,ignored,seen);
   else if(left instanceof COSArray a){COSArray b=(COSArray)right;if(a.size()!=b.size())throw new SecurityException("PDF array changed");for(int i=0;i<a.size();i++)deepEqual(a.get(i),b.get(i),Set.of(),seen);}
   else if(!left.toString().equals(right.toString()))throw new SecurityException("PDF value changed");
 }
 private static void compareDictionaries(COSDictionary a,COSDictionary b,Set<COSName> ignored,Set<BasePair> seen)throws IOException {
   Set<COSName> ak=new HashSet<>(a.keySet()),bk=new HashSet<>(b.keySet());ak.removeAll(ignored);bk.removeAll(ignored);
   if(!ak.equals(bk))throw new SecurityException("PDF dictionary changed");
   for(COSName key:ak)deepEqual(a.getItem(key),b.getItem(key),Set.of(),seen);
 }
 private static COSBase deref(COSBase value){while(value instanceof COSObject object)value=object.getObject();return value;}
 private static final class BasePair {
   final COSBase a,b;BasePair(COSBase a,COSBase b){this.a=a;this.b=b;}
   public boolean equals(Object o){return o instanceof BasePair p&&p.a==a&&p.b==b;}
   public int hashCode(){return System.identityHashCode(a)*31+System.identityHashCode(b);}
 }
 private static Metadata verifyCms(byte[] content,byte[] cms,String expected)throws Exception {
   CMSSignedData data=new CMSSignedData(new CMSProcessableByteArray(content),cms);
   SignerInformationStore infos=data.getSignerInfos(); if(infos.size()!=1)throw new SecurityException("exactly one signer is required");
   SignerInformation info=infos.getSigners().iterator().next(); Store<X509CertificateHolder> certs=data.getCertificates();
    Iterator<?> matching=certs.getMatches(info.getSID()).iterator();
    if(!matching.hasNext()) throw new SecurityException("signing certificate missing");
    X509CertificateHolder h=(X509CertificateHolder)matching.next();
   X509Certificate cert=new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(h);
   if(!info.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)))throw new SecurityException("CMS integrity check failed");
   cert.checkValidity(); boolean[] usage=cert.getKeyUsage(); if(usage!=null&&!usage[0]&&!usage[1])throw new SecurityException("certificate lacks signing key usage");
   String cpf=cpfFromSan(cert);if(cpf==null||!cpf.equals(expected))throw new SecurityException("certificate CPF does not match expected doctor CPF");
    validateChain(cert,certs);
    return new Metadata(cpf, cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName(), cert.getSerialNumber().toString(16));
 }
 static void validateChain(X509Certificate signer,Store<X509CertificateHolder> holders)throws Exception {
   Set<TrustAnchor> anchors=loadTrustAnchors();
   List<X509Certificate> cmsCertificates=new ArrayList<>();
   for(X509CertificateHolder h:holders.getMatches(null))
     cmsCertificates.add(new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(h));
   X509CertSelector target=new X509CertSelector();target.setCertificate(signer);
   PKIXBuilderParameters parameters=new PKIXBuilderParameters(anchors,target);
   parameters.addCertStore(CertStore.getInstance("Collection",new CollectionCertStoreParameters(cmsCertificates)));
   parameters.setRevocationEnabled(true);
   System.setProperty("com.sun.security.enableCRLDP","true");
   Security.setProperty("ocsp.enable","true");
   CertPathBuilder builder=CertPathBuilder.getInstance("PKIX");
   PKIXRevocationChecker revocation=(PKIXRevocationChecker)builder.getRevocationChecker();
   // The default hard-fail behavior tries OCSP and falls back to CRLs. Never add SOFT_FAIL.
   revocation.setOptions(EnumSet.noneOf(PKIXRevocationChecker.Option.class));
   parameters.addCertPathChecker(revocation);
   builder.build(parameters);
 }
 static Set<TrustAnchor> loadTrustAnchors()throws Exception {
   Set<TrustAnchor> anchors=new HashSet<>();
   CertificateFactory factory=CertificateFactory.getInstance("X.509");
   for(Map.Entry<String,String> pin:ICP_BRASIL_ROOTS.entrySet()){
     String resource="/icpbrasil/"+pin.getKey(); byte[] resourceBytes;
     try(InputStream in=ValidationCli.class.getResourceAsStream(resource)){
       if(in==null)throw new CertificateException("required trust anchor missing");
       resourceBytes=in.readAllBytes();
     }
     X509Certificate root=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(resourceBytes));
     String digest=HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(root.getEncoded()));
     if(!MessageDigest.isEqual(digest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),pin.getValue().getBytes(java.nio.charset.StandardCharsets.US_ASCII)))
       throw new CertificateException("trust anchor pin mismatch");
     if(!root.getSubjectX500Principal().equals(root.getIssuerX500Principal())||root.getBasicConstraints()<0)
       throw new CertificateException("invalid trust anchor constraints");
     try {
       root.verify(root.getPublicKey(),new org.bouncycastle.jce.provider.BouncyCastleProvider());
     } catch(NoSuchAlgorithmException unsupported) {
       // AC Raiz v7 uses ITI's 1.3.6.1.4.1.44588.2.1 algorithm, which Java 17
       // and BC cannot execute. Only the byte-for-byte pinned v7 certificate
       // may take this path; every executable root signature is verified.
       if(!"ICP-Brasilv7.crt".equals(pin.getKey())
         ||!"1.3.6.1.4.1.44588.2.1".equals(root.getSigAlgOID())
         ||!root.getSigAlgOID().equals(root.getPublicKey().getAlgorithm())
         ||root.getSignature().length==0) throw unsupported;
     }
     anchors.add(new TrustAnchor(root,null));
   }
   if(anchors.size()!=ICP_BRASIL_ROOTS.size())throw new CertificateException("trust anchor set incomplete");
   return Collections.unmodifiableSet(anchors);
 }
 static String cpfFromSan(X509Certificate cert)throws Exception {
   byte[] ext=cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName.getId());if(ext==null)return null;
   GeneralNames names=GeneralNames.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(ext)).getOctets()));
    for(GeneralName n:names.getNames())if(n.getTagNo()==GeneralName.otherName){ASN1Sequence s=ASN1Sequence.getInstance(n.getName());if(s.size()>1&&new ASN1ObjectIdentifier("2.16.76.1.3.1").equals(s.getObjectAt(0))){ASN1TaggedObject v=ASN1TaggedObject.getInstance(s.getObjectAt(1));ASN1Encodable value=v.getBaseObject();if(value instanceof ASN1String text){String raw=text.getString();String candidate=null;if(raw.matches("\\d{11}"))candidate=raw;else if(raw.length()>=19&&raw.substring(8,19).matches("\\d{11}"))candidate=raw.substring(8,19);if(candidate!=null&&validCpf(candidate))return candidate;}}}
   return null;
 }
 static String normalizeCpf(String s) {
   String value=s.replaceAll("\\D","");
   if(!validCpf(value))throw new SecurityException("invalid expected CPF");
   return value;
 }
 static boolean validCpf(String value) {
   if(value==null||!value.matches("\\d{11}")||value.chars().distinct().count()==1)return false;
   int first=0;for(int i=0;i<9;i++)first+=(value.charAt(i)-'0')*(10-i);
   first=11-(first%11);if(first>=10)first=0;if(first!=value.charAt(9)-'0')return false;
   int second=0;for(int i=0;i<10;i++)second+=(value.charAt(i)-'0')*(11-i);
   second=11-(second%11);if(second>=10)second=0;return second==value.charAt(10)-'0';
 }
 private static String errorCode(Exception e) {
   if(e instanceof java.nio.file.NoSuchFileException) return "INPUT_UNAVAILABLE";
   if(e instanceof SecurityException) return "VALIDATION_REJECTED";
   if(e instanceof CertPathValidatorException || e instanceof CertificateException) return "CERTIFICATE_INVALID";
   return "VALIDATION_ERROR";
 }
 private static void out(boolean ok,String reason){System.out.println("{\"valid\":"+ok+",\"errorCode\":\""+reason+"\"}");}
 private static void outSuccess(Metadata m) {
   System.out.println("{\"valid\":true,\"protocol\":\"ETSI.CAdES.detached\",\"cpf\":\""+m.cpf+"\",\"certificateSubject\":\""+json(m.subject)+"\",\"certificateIssuer\":\""+json(m.issuer)+"\",\"certificateSerial\":\""+m.serial+"\"}");
 }
 private static String json(String s){return s.replace("\\","\\\\").replace("\"","\\\"").replace("\r","").replace("\n","");}
 private static final class Metadata {
   final String cpf,subject,issuer,serial;
   Metadata(String cpf,String subject,String issuer,String serial){this.cpf=cpf;this.subject=subject;this.issuer=issuer;this.serial=serial;}
 }
}