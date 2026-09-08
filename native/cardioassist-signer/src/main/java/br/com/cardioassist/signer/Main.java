package br.com.cardioassist.signer;

import javax.swing.*;
import java.net.URI;
import java.nio.file.Path;

/** Desktop entry point. No credential, PIN, token, or key material is logged. */
public final class Main {
  public static void main(String[] args) {
    if (args.length > 0 && "--validate".equals(args[0])) {
      System.exit(ValidationCli.run(args));
      return;
    }
    UriRequest.LaunchRequest request = args.length == 1 ? UriRequest.parse(args[0]) : null;
    SwingUtilities.invokeLater(() -> new SignerFrame(request).setVisible(true));
  }
}