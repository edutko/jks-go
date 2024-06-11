package com.edutko;

import java.io.File;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class Main {
    public static void main(String[] args) throws Exception {
        try {
            if (args.length > 1 && !args[1].isEmpty()) {
                printEntries(args[0], args[1].toCharArray());
            } else {
                printEntries(args[0], null);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private static void printEntries(String fileName, char[] password) throws Exception {
        File f = new File(fileName);
        KeyStore keystore = KeyStore.getInstance(f, password);

        System.out.println("{");
        System.out.println("  \"type\": \"" + keystore.getType() + "\",");
        System.out.println("  \"entries\": {");

        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);
            if (keystore.isCertificateEntry(alias)) {
                protection = null;
            }
            Date ts = keystore.getCreationDate(alias);
            String creationDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX").format(ts);
            String entryType = "";
            String algorithm = "";
            String format = "";
            LinkedList<byte[]> items = new LinkedList<>();

            KeyStore.Entry e = keystore.getEntry(alias, protection);
            if (e instanceof KeyStore.PrivateKeyEntry) {
                Key key = keystore.getKey(alias, password);
                entryType = "PrivateKeyEntry";
                algorithm = key.getAlgorithm();
                format = key.getFormat();
                items.add(key.getEncoded());

                Certificate[] chain = keystore.getCertificateChain(alias);
                if (chain != null) {
                    for (Certificate cert : chain) {
                        items.add(cert.getEncoded());
                    }
                } else {
                    Certificate cert = keystore.getCertificate(alias);
                    if (cert != null) {
                        items.add(cert.getEncoded());
                    }
                }

            } else if (e instanceof KeyStore.SecretKeyEntry) {
                Key key = keystore.getKey(alias, password);
                entryType = "SecretKeyEntry";
                algorithm = key.getAlgorithm();
                format = key.getFormat();
                items.add(key.getEncoded());

            } else if (e instanceof KeyStore.TrustedCertificateEntry) {
                entryType = "trustedCertEntry";
                Certificate[] chain = keystore.getCertificateChain(alias);
                if (chain != null) {
                    for (Certificate cert : chain) {
                        items.add(cert.getEncoded());
                    }
                } else {
                    Certificate cert = keystore.getCertificate(alias);
                    if (cert != null) {
                        items.add(cert.getEncoded());
                    }
                }

            } else {
                throw new RuntimeException("unknown entry type for " + alias);
            }

            System.out.println("    \"" + alias + "\": {");
            System.out.println("      \"creationDate\": \"" + creationDate + "\",");
            System.out.println("      \"entryType\": \"" + entryType + "\",");
            System.out.println("      \"algorithm\": \"" + algorithm + "\",");
            System.out.println("      \"format\": \"" + format + "\",");
            System.out.println("      \"items\": [");
            if (!items.isEmpty()) {
                System.out.println("          \"" + items.stream().map(Base64.getEncoder()::encodeToString).collect(Collectors.joining("\",\n          \"")) + "\"");
            }
            System.out.println("      ]");
            if (aliases.hasMoreElements()) {
                System.out.println("    },");
            } else {
                System.out.println("    }");
            }
        }
        System.out.println("  }");
        System.out.println("}");
    }
}
