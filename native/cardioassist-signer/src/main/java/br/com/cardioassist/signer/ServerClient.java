package br.com.cardioassist.signer;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.HexFormat;

/** Deliberately uses a small, explicit protocol; endpoints must be served over HTTPS. */
final class ServerClient {
  static final Duration CONNECT_TIMEOUT=Duration.ofSeconds(10);
  static final Duration CONTROL_TIMEOUT=Duration.ofSeconds(15);
  static final Duration TRANSFER_TIMEOUT=Duration.ofSeconds(90);
  private static final int MAX_ATTEMPTS=3;
  private final URI base;
  private final HttpClient http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
  ServerClient() {
    base = URI.create(System.getProperty("cardioassist.baseUrl", "https://cardioassistant.top"));
    if (!"https".equalsIgnoreCase(base.getScheme())) throw new IllegalStateException("CardioAssist URL must use HTTPS");
  }
  Session claim(UriRequest.LaunchRequest request) throws IOException, InterruptedException {
    HttpRequest r = HttpRequest.newBuilder(base.resolve("/api/signer/sessions/" + request.session() + "/claim"))
      .timeout(CONTROL_TIMEOUT).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString("{\"launchCode\":\""+json(request.launch())+"\"}")).build();
    HttpResponse<String> x=http.send(r,HttpResponse.BodyHandlers.ofString());
    if(x.statusCode()/100!=2) throw new IOException("Pairing request was rejected ("+x.statusCode()+")");
    return Session.fromClaimJson(request.session(), request.pairing(), x.body());
  }
  String status(Session s) throws IOException, InterruptedException {
    return retry("session status",()->{
      HttpResponse<String> x=http.send(auth(s, "/api/signer/sessions/"+s.id,CONTROL_TIMEOUT).GET().build(),HttpResponse.BodyHandlers.ofString());
      requireSuccess(x.statusCode(),"Session status request");return value(x.body(),"state");
    });
  }
  void download(Session s, Path target) throws IOException, InterruptedException {
    byte[] bytes=retry("PDF download",()->{
      HttpRequest r=auth(s, "/api/signer/sessions/"+s.id+"/document",TRANSFER_TIMEOUT).GET().build();
      HttpResponse<byte[]>x=http.send(r,HttpResponse.BodyHandlers.ofByteArray());
      requireSuccess(x.statusCode(),"PDF download");return x.body();
    });
    Files.write(target,bytes,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);
  }
  void upload(Session s, Path signed) throws IOException, InterruptedException {
    String digest=sha256Hex(signed);
    retry("signed PDF upload",()->{
      HttpResponse<Void>x=http.send(uploadRequest(s,signed,digest),HttpResponse.BodyHandlers.discarding());
      requireSuccess(x.statusCode(),"Signed PDF upload");return null;
    });
  }
  HttpRequest uploadRequest(Session s,Path signed,String digest)throws IOException{
    return auth(s,"/api/signer/sessions/"+s.id+"/signed-pdf",TRANSFER_TIMEOUT).header("Content-Type","application/pdf")
      .header("X-Content-SHA256",digest).POST(HttpRequest.BodyPublishers.ofFile(signed)).build();
  }
  private HttpRequest.Builder auth(Session s,String path,Duration timeout){return HttpRequest.newBuilder(base.resolve(path)).timeout(timeout).header("Authorization","Bearer "+s.token);}
  static String sha256Hex(Path file)throws IOException{
    try{
      MessageDigest digest=MessageDigest.getInstance("SHA-256");
      try(var in=Files.newInputStream(file)){byte[] block=new byte[8192];for(int n;(n=in.read(block))>=0;)if(n>0)digest.update(block,0,n);}
      return HexFormat.of().formatHex(digest.digest());
    }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException("SHA-256 unavailable",impossible);}
  }
  private static void requireSuccess(int status,String operation)throws RequestFailure {
    if(status/100!=2)throw new RequestFailure(operation+" failed ("+status+")",status);
  }
  private static boolean retryable(Throwable failure){
    if(failure instanceof RequestFailure r)return r.status==408||r.status==429||r.status>=500;
    return failure instanceof IOException;
  }
  private static <T>T retry(String operation,Attempt<T> attempt)throws IOException,InterruptedException{
    IOException last=null;
    for(int count=1;count<=MAX_ATTEMPTS;count++){
      try{return attempt.run();}
      catch(InterruptedException interrupted){throw interrupted;}
      catch(IOException failure){
        if(!retryable(failure))throw failure;last=failure;
        if(count<MAX_ATTEMPTS)Thread.sleep(250L*count);
      }
    }
    throw new IOException(operation+" failed after "+MAX_ATTEMPTS+" attempts. Check the network and try again.",last);
  }
  private static final class RequestFailure extends IOException{final int status;RequestFailure(String message,int status){super(message);this.status=status;}}
  @FunctionalInterface private interface Attempt<T>{T run()throws IOException,InterruptedException;}
  private static String json(String v){return v.replace("\\","\\\\").replace("\"","\\\"");}
  record Session(String id,String token,String pairing) {
    static Session fromClaimJson(String id, String pairing, String s) {
      return new Session(id,value(s,"sessionToken"),pairing);
    }
  }
  private static String value(String s,String key) {
      var m=java.util.regex.Pattern.compile("\""+key+"\"\\s*:\\s*\"([^\"]+)\"").matcher(s);
      if(!m.find())throw new IllegalArgumentException("Malformed server session response"); return m.group(1);
  }
}