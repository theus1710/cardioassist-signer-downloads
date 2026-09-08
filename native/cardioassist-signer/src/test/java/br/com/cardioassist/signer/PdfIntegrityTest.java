package br.com.cardioassist.signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.*;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.awt.Color;
import static org.junit.jupiter.api.Assertions.*;

class PdfIntegrityTest {
  @Test void ownEcSignatureIsSignatureOnlyAndAppendedBytesAreRejected()throws Exception {
    Path original=pdf(),signed=Files.createTempFile("signed-", ".pdf");
    try{
      PdfSigner.sign(original,signed,material("EC"));
      try(PDDocument a=Loader.loadPDF(original.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        var signature=b.getSignatureDictionaries().get(0);
        ValidationCli.validateSignatureOnlyRevision(a,b,signature);
        ValidationCli.validateByteRange(Files.readAllBytes(signed),signature.getByteRange());
        byte[] appended=Arrays.copyOf(Files.readAllBytes(signed),Math.toIntExact(Files.size(signed)+5));
        assertThrows(SecurityException.class,()->ValidationCli.validateByteRange(appended,signature.getByteRange()));
      }
    }finally{Files.deleteIfExists(original);Files.deleteIfExists(signed);}
  }
  @Test void pageAddedInIntermediateRevisionIsRejectedEvenWhenLaterSigned()throws Exception {
    Path original=pdf(),changed=Files.createTempFile("changed-", ".pdf"),signed=Files.createTempFile("signed-", ".pdf");
    try{
      try(PDDocument d=Loader.loadPDF(original.toFile());var out=Files.newOutputStream(changed)){d.addPage(new PDPage());d.saveIncremental(out);}
      PdfSigner.sign(changed,signed,material("RSA"));
      try(PDDocument a=Loader.loadPDF(original.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        assertThrows(SecurityException.class,()->ValidationCli.validateSignatureOnlyRevision(a,b,b.getSignatureDictionaries().get(0)));
      }
    }finally{Files.deleteIfExists(original);Files.deleteIfExists(changed);Files.deleteIfExists(signed);}
  }
  @Test void hiddenJavaScriptActionIsRejected()throws Exception {
    Path active=Files.createTempFile("active-", ".pdf"),signed=Files.createTempFile("signed-", ".pdf");
    try{
      try(PDDocument d=new PDDocument()){d.addPage(new PDPage());d.getDocumentCatalog().setOpenAction(new PDActionJavaScript("app.alert('x')"));d.save(active.toFile());}
      PdfSigner.sign(active,signed,material("RSA"));
      try(PDDocument a=Loader.loadPDF(active.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        assertThrows(SecurityException.class,()->ValidationCli.validateSignatureOnlyRevision(a,b,b.getSignatureDictionaries().get(0)));
      }
    }finally{Files.deleteIfExists(active);Files.deleteIfExists(signed);}
  }
  @Test void fullPageWhiteSignatureAppearanceOverlayIsRejected()throws Exception {
    Path original=pdf(),signed=Files.createTempFile("signed-", ".pdf");
    try{
      PdfSigner.sign(original,signed,material("RSA"));
      try(PDDocument a=Loader.loadPDF(original.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        ValidationCli.validateSignatureOnlyRevision(a,b,b.getSignatureDictionaries().get(0));
      }
      try(PDDocument a=Loader.loadPDF(original.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        var signature=b.getSignatureDictionaries().get(0);
        var form=(org.apache.pdfbox.cos.COSDictionary)b.getDocumentCatalog().getCOSObject().getDictionaryObject(org.apache.pdfbox.cos.COSName.ACRO_FORM);
        var fields=form.getCOSArray(org.apache.pdfbox.cos.COSName.FIELDS);
        var widget=(org.apache.pdfbox.cos.COSDictionary)fields.getObject(0);
        PDRectangle fullPage=b.getPage(0).getMediaBox();widget.setItem(org.apache.pdfbox.cos.COSName.RECT,fullPage.getCOSArray());
        PDAppearanceStream white=new PDAppearanceStream(b);white.setBBox(fullPage);
        try(PDPageContentStream content=new PDPageContentStream(b,white)){content.setNonStrokingColor(Color.WHITE);content.addRect(0,0,fullPage.getWidth(),fullPage.getHeight());content.fill();}
        var appearance=new org.apache.pdfbox.cos.COSDictionary();appearance.setItem(org.apache.pdfbox.cos.COSName.N,white);widget.setItem(org.apache.pdfbox.cos.COSName.AP,appearance);
        assertThrows(SecurityException.class,()->ValidationCli.validateSignatureOnlyRevision(a,b,signature));
      }
    }finally{Files.deleteIfExists(original);Files.deleteIfExists(signed);}
  }
  @Test void inheritedPageAttributeReplacementIsRejected()throws Exception {
    Path original=Files.createTempFile("inherited-", ".pdf"),signed=Files.createTempFile("signed-", ".pdf");
    try{
      try(PDDocument d=new PDDocument()){
        PDPage page=new PDPage();d.addPage(page);page.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.MEDIA_BOX);
        d.getDocumentCatalog().getPages().getCOSObject().setItem(org.apache.pdfbox.cos.COSName.MEDIA_BOX,PDRectangle.A4.getCOSArray());d.save(original.toFile());
      }
      PdfSigner.sign(original,signed,material("RSA"));
      try(PDDocument a=Loader.loadPDF(original.toFile());PDDocument b=Loader.loadPDF(signed.toFile())){
        b.getDocumentCatalog().getPages().getCOSObject().setItem(org.apache.pdfbox.cos.COSName.MEDIA_BOX,PDRectangle.LETTER.getCOSArray());
        assertThrows(SecurityException.class,()->ValidationCli.validateSignatureOnlyRevision(a,b,b.getSignatureDictionaries().get(0)));
      }
    }finally{Files.deleteIfExists(original);Files.deleteIfExists(signed);}
  }
  private static Path pdf()throws Exception{
    Path p=Files.createTempFile("original-", ".pdf");try(PDDocument d=new PDDocument()){d.addPage(new PDPage());d.save(p.toFile());}return p;
  }
  private static CertificateChoice material(String algorithm)throws Exception{
    KeyPairGenerator generator=KeyPairGenerator.getInstance(algorithm);if("RSA".equals(algorithm))generator.initialize(2048);else generator.initialize(256);
    KeyPair pair=generator.generateKeyPair();X500Name name=new X500Name("CN=Integrity Test");
    var builder=new JcaX509v3CertificateBuilder(name,BigInteger.valueOf(System.nanoTime()),new Date(System.currentTimeMillis()-1000),new Date(System.currentTimeMillis()+60000),name,pair.getPublic());
    String signature="EC".equals(algorithm)?"SHA256withECDSA":"SHA256withRSA";
    X509Certificate certificate=new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(signature).build(pair.getPrivate())));
    return new CertificateChoice(null,"test",pair.getPrivate(),certificate,new X509Certificate[]{certificate});
  }
}