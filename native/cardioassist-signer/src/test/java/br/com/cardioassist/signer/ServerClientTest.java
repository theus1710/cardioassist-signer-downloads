package br.com.cardioassist.signer;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

class ServerClientTest {
  @Test void formatsLowercaseSha256AndAddsUploadHeaderAndDeadline()throws Exception{
    Path pdf=Files.createTempFile("digest-", ".pdf");
    try{
      Files.write(pdf,"abc".getBytes(StandardCharsets.US_ASCII));
      String digest=ServerClient.sha256Hex(pdf);
      assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",digest);
      assertTrue(digest.matches("[0-9a-f]{64}"));
      ServerClient client=new ServerClient();
      var request=client.uploadRequest(new ServerClient.Session("1","abcdefghijklmnopqrstuvwxyzABCDEFG_1234567890","pairing"),pdf,digest);
      assertEquals(digest,request.headers().firstValue("X-Content-SHA256").orElseThrow());
      assertEquals(ServerClient.TRANSFER_TIMEOUT,request.timeout().orElseThrow());
      assertTrue(ServerClient.CONNECT_TIMEOUT.compareTo(Duration.ZERO)>0);
      assertTrue(ServerClient.CONTROL_TIMEOUT.compareTo(Duration.ZERO)>0);
    }finally{Files.deleteIfExists(pdf);}
  }
}