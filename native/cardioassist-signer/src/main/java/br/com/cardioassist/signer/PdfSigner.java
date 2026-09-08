package br.com.cardioassist.signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.interactive.form.*;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import java.io.*; import java.nio.file.*; import java.security.*; import java.security.cert.X509Certificate; import java.util.*;

final class PdfSigner {
  static void sign(Path input, Path output, CertificateChoice choice) throws Exception {
    try (PDDocument doc=Loader.loadPDF(input.toFile()); OutputStream out=Files.newOutputStream(output)) {
      PDSignature sig=new PDSignature();
      sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      sig.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      sig.setName(choice.certificate().getSubjectX500Principal().getName());
      sig.setSignDate(Calendar.getInstance());
      doc.addSignature(sig);
      makeSignatureWidgetInvisible(doc);
      ExternalSigningSupport ext=doc.saveIncrementalForExternalSigning(out);
      ext.setSignature(cms(ext.getContent(),choice));
    }
  }
  private static void makeSignatureWidgetInvisible(PDDocument doc) {
    PDAcroForm form=doc.getDocumentCatalog().getAcroForm();
    if(form==null)throw new IllegalStateException("PDFBox did not create a signature field");
    PDSignatureField field=null;
    for(PDField candidate:form.getFieldTree())if(candidate instanceof PDSignatureField signatureField){if(field!=null)throw new IllegalStateException("multiple signature fields");field=signatureField;}
    if(field==null||field.getWidgets().size()!=1)throw new IllegalStateException("missing signature widget");
    var widget=field.getWidgets().get(0);
    var dictionary=widget.getCOSObject();
    for(String key:List.of("Rect","AP","MK","DA","BS","Border","C","OC","A","AA","TU","TM","TOpt"))
      dictionary.removeItem(org.apache.pdfbox.cos.COSName.getPDFName(key));
    dictionary.setInt(org.apache.pdfbox.cos.COSName.F,1|2|32);
    form.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.DA);
    form.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.DR);
  }
  private static byte[] cms(InputStream signedContent, CertificateChoice c) throws Exception {
    CMSSignedDataGenerator g=new CMSSignedDataGenerator();
    String keyAlgorithm=c.key().getAlgorithm();
    String signatureAlgorithm=("EC".equalsIgnoreCase(keyAlgorithm)||keyAlgorithm.toUpperCase(Locale.ROOT).startsWith("EC_"))
      ?"SHA256withECDSA":"SHA256with"+keyAlgorithm;
    ContentSigner signer=new JcaContentSignerBuilder(signatureAlgorithm).build(c.key());
    g.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
      new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()).build(signer,c.certificate()));
    g.addCertificates(new JcaCertStore(Arrays.asList(c.chain())));
    return g.generate(new CMSProcessableInputStream(signedContent), false).getEncoded();
  }
  private static final class CMSProcessableInputStream implements CMSTypedData {
    private final InputStream in; CMSProcessableInputStream(InputStream in){this.in=in;}
    public org.bouncycastle.asn1.ASN1ObjectIdentifier getContentType(){return CMSObjectIdentifiers.data;}
    public Object getContent(){return in;}
    public void write(OutputStream out)throws IOException {in.transferTo(out);}
  }
}