package br.com.cardioassist.signer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

final class SignerFrame extends JFrame {
  private final JTextField code=new JTextField();
  private final JTextArea status=new JTextArea(8,50);
  private final UriRequest.LaunchRequest launchRequest;
  private final AtomicBoolean busy=new AtomicBoolean();
  private final List<JButton> buttons=new ArrayList<>();
  private volatile CertificateChoice selected;
  private volatile ServerClient.Session session;
  private volatile Path unsigned;

  SignerFrame(UriRequest.LaunchRequest incoming) {
    super("CardioAssist Signer");
    launchRequest=incoming;setDefaultCloseOperation(EXIT_ON_CLOSE);setSize(620,390);setLocationByPlatform(true);
    code.setText(incoming==null?"":incoming.pairing());code.setEditable(false);status.setEditable(false);status.setLineWrap(true);
    JPanel top=new JPanel(new BorderLayout(8,8));top.add(new JLabel("Pairing code:"),BorderLayout.WEST);top.add(code);
    JPanel controls=new JPanel();
    JButton pair=button("Pair and download"),pfx=button("Choose A1 PFX/P12"),system=button("System/A3 certificate"),sign=button("Confirm, sign and upload");
    controls.add(pair);controls.add(pfx);controls.add(system);controls.add(sign);
    add(top,BorderLayout.NORTH);add(new JScrollPane(status),BorderLayout.CENTER);add(controls,BorderLayout.SOUTH);
    pair.addActionListener(e->background(this::pair));
    pfx.addActionListener(e->choosePfx());
    system.addActionListener(e->background(this::chooseSystem));
    sign.addActionListener(e->beginSign());
    addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent e){deleteTree(unsigned);}});
    showStatus(incoming==null?"Open this application using a CardioAssist signing link.":"Pairing code: "+incoming.pairing()+"\nReady to claim session. Credentials and PINs remain local.");
  }
  private JButton button(String text){JButton b=new JButton(text);buttons.add(b);return b;}
  private void background(Task task) {
    if(!busy.compareAndSet(false,true))return;
    setButtons(false);
    new SwingWorker<Void,Void>(){
      protected Void doInBackground()throws Exception{task.go();return null;}
      protected void done(){try{get();}catch(InterruptedException x){Thread.currentThread().interrupt();showStatus("Operation interrupted. Please try again.");}catch(ExecutionException x){String message=x.getCause()==null?null:x.getCause().getMessage();showStatus(message==null||message.isBlank()?"Operation failed. Please try again.":"Operation failed: "+message);}finally{busy.set(false);setButtons(true);}}
    }.execute();
  }
  private void pair()throws Exception {
    if(launchRequest==null)throw new IllegalStateException("Missing launch request");
    if(session!=null||unsigned!=null)throw new IllegalStateException("Session has already been claimed");
    ServerClient client=new ServerClient();session=client.claim(launchRequest);
    showStatus("Pairing code: "+session.pairing()+"\nWaiting for browser approval...");
    while(true){String state=client.status(session);if("APPROVED".equals(state))break;if(!"CLAIMED".equals(state))throw new IllegalStateException("Session unavailable");Thread.sleep(1500);}
    Path target=Files.createTempFile("cardioassist-unsigned-", ".pdf");
    try{client.download(session,target);unsigned=target;}catch(Exception x){deleteTree(target);throw x;}
    showStatus("Browser approval received. PDF downloaded. Choose your signing certificate.");
  }
  private void choosePfx() {
    if(busy.get())return;
    JFileChooser chooser=new JFileChooser();if(chooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;
    JPasswordField password=new JPasswordField();if(JOptionPane.showConfirmDialog(this,password,"PFX password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
    char[] secret=password.getPassword();Path file=chooser.getSelectedFile().toPath();
    background(()->{try{CertificateChoice choice=CertificateStores.pfx(file,secret);confirmOnEdt(choice);}finally{Arrays.fill(secret,'\0');}});
  }
  private void chooseSystem()throws Exception {
    List<CertificateChoice> choices=CertificateStores.system();
    if(choices.isEmpty())throw new IllegalStateException("No system certificate found");
    CertificateChoice choice=onEdt(()->{
      Object picked=JOptionPane.showInputDialog(this,"Choose certificate","System/A3 certificates",JOptionPane.PLAIN_MESSAGE,null,choices.stream().map(CertificateChoice::summary).toArray(),null);
      if(picked==null)return null;return choices.get(choices.stream().map(CertificateChoice::summary).toList().indexOf(picked));
    });
    if(choice!=null)confirmOnEdt(choice);
  }
  private void confirmOnEdt(CertificateChoice choice)throws Exception {
    boolean accepted=onEdt(()->JOptionPane.showConfirmDialog(this,choice.summary()+"\n\nUse this certificate?","Explicit certificate confirmation",JOptionPane.YES_NO_OPTION)==JOptionPane.YES_OPTION);
    if(accepted){selected=choice;showStatus("Certificate selected:\n"+choice.summary());}
  }
  private void beginSign() {
    if(busy.get())return;
    if(session==null||unsigned==null){showStatus("Pair and download the PDF first.");return;}
    CertificateChoice choice=selected;if(choice==null){showStatus("Choose and confirm a certificate first.");return;}
    char[] pin=null;
    if(choice.key()==null){JPasswordField field=new JPasswordField();if(JOptionPane.showConfirmDialog(this,field,"Token PIN (not stored)",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;pin=field.getPassword();}
    final char[] secret=pin;
    background(()->sign(choice,secret));
  }
  private void sign(CertificateChoice choice,char[] pin)throws Exception {
    Path output=null;
    try{
      CertificateChoice use=choice;if(use.key()==null)use=CertificateStores.unlock(use,pin);
      output=Files.createTempFile("cardioassist-signed-", ".pdf");PdfSigner.sign(unsigned,output,use);new ServerClient().upload(session,output);
      showStatus("Signed PDF uploaded successfully.");
    }finally{
      if(pin!=null)Arrays.fill(pin,'\0');
      deleteTree(output);Path input=unsigned;unsigned=null;deleteTree(input);
    }
  }
  private void showStatus(String text){if(SwingUtilities.isEventDispatchThread())status.setText(text);else SwingUtilities.invokeLater(()->status.setText(text));}
  private void setButtons(boolean enabled){Runnable r=()->buttons.forEach(b->b.setEnabled(enabled));if(SwingUtilities.isEventDispatchThread())r.run();else SwingUtilities.invokeLater(r);}
  private static <T>T onEdt(Callable<T> action)throws Exception {
    if(SwingUtilities.isEventDispatchThread())return action.call();
    FutureTask<T> task=new FutureTask<>(action);SwingUtilities.invokeAndWait(task);return task.get();
  }
  private static void deleteTree(Path path) {
    if(path==null)return;
    try(var walk=Files.walk(path)){walk.sorted(Comparator.reverseOrder()).forEach(p->{try{Files.deleteIfExists(p);}catch(Exception ignored){}});}catch(Exception ignored){}
  }
  @FunctionalInterface private interface Task{void go()throws Exception;}
}