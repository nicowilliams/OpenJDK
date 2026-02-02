/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import org.ietf.jgss.*;

import java.io.Console;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * A standalone kinit-like utility using GSS-API.
 *
 * This tool demonstrates acquiring Kerberos credentials using:
 * 1. Password authentication via GSSManager.createCredential(name, password, ...)
 * 2. Keytab authentication via GSSManager.createCredential(name, store, ...)
 *
 * And storing them using:
 * 1. GSSCredential.storeInto() for native GSS
 * 2. Fallback to internal APIs for Java Krb5
 *
 * Usage:
 *   java KinitTool [-k keytab] [-c ccache] [-l lifetime] principal
 *
 * Options:
 *   -k keytab   : Use keytab file for authentication (like kinit -k)
 *   -c ccache   : Write credentials to specified ccache file
 *   -l lifetime : Request specific lifetime in seconds
 *   principal   : The Kerberos principal (e.g., user@REALM)
 *
 * Examples:
 *   # Authenticate with password, store to default ccache
 *   java KinitTool user@EXAMPLE.COM
 *
 *   # Authenticate with keytab
 *   java KinitTool -k /etc/krb5.keytab host/server.example.com@EXAMPLE.COM
 *
 *   # Authenticate and store to specific ccache
 *   java KinitTool -c /tmp/krb5cc_myapp user@EXAMPLE.COM
 *
 * Note: For storeInto() to work, you need native GSS:
 *   java -Dsun.security.jgss.native=true KinitTool ...
 */
public class KinitTool {

    private static final Oid KRB5_MECH;
    private static final Oid KRB5_PRINCIPAL_NT;

    static {
        try {
            KRB5_MECH = new Oid("1.2.840.113554.1.2.2");
            KRB5_PRINCIPAL_NT = new Oid("1.2.840.113554.1.2.2.1");
        } catch (GSSException e) {
            throw new RuntimeException("Failed to initialize OIDs", e);
        }
    }

    public static void main(String[] args) throws Exception {
        String principal = null;
        String keytab = null;
        String ccache = null;
        int lifetime = GSSCredential.DEFAULT_LIFETIME;

        // Parse arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-k":
                    if (++i >= args.length) usage("Missing keytab path");
                    keytab = args[i];
                    break;
                case "-c":
                    if (++i >= args.length) usage("Missing ccache path");
                    ccache = args[i];
                    break;
                case "-l":
                    if (++i >= args.length) usage("Missing lifetime value");
                    lifetime = Integer.parseInt(args[i]);
                    break;
                case "-h":
                case "--help":
                    usage(null);
                    break;
                default:
                    if (args[i].startsWith("-")) {
                        usage("Unknown option: " + args[i]);
                    }
                    principal = args[i];
            }
        }

        if (principal == null) {
            usage("Principal is required");
        }

        // Determine default ccache location if not specified
        if (ccache == null) {
            String krbCcname = System.getenv("KRB5CCNAME");
            if (krbCcname != null) {
                ccache = krbCcname.startsWith("FILE:") ?
                        krbCcname.substring(5) : krbCcname;
            } else {
                ccache = "/tmp/krb5cc_" + getUid();
            }
        }

        GSSCredential cred;
        if (keytab != null) {
            cred = acquireFromKeytab(principal, keytab, lifetime);
        } else {
            cred = acquireWithPassword(principal, lifetime);
        }

        // Store to ccache
        storeToCcache(cred, ccache);

        // Print ticket info (like klist)
        System.out.println();
        System.out.println("Ticket cache: FILE:" + ccache);
        System.out.println("Default principal: " + cred.getName());
        System.out.println();
        System.out.println("Valid starting       Expires              Service principal");

        // Get ticket info
        int remaining = cred.getRemainingLifetime();
        long now = System.currentTimeMillis();
        long expires = now + (remaining * 1000L);

        System.out.printf("%s  %s  krbtgt/%s@%s%n",
                formatTime(now),
                formatTime(expires),
                getRealm(principal),
                getRealm(principal));

        cred.dispose();
    }

    /**
     * Acquire credentials using password
     */
    static GSSCredential acquireWithPassword(String principal, int lifetime)
            throws Exception {
        GSSManager manager = GSSManager.getInstance();

        // Create the name
        GSSName name = manager.createName(principal, KRB5_PRINCIPAL_NT);

        // Get password
        String password = readPassword("Password for " + principal + ": ");

        // Acquire credentials
        System.out.println("Acquiring credentials for " + principal + "...");
        return manager.createCredential(
                name,
                password,
                lifetime,
                KRB5_MECH,
                GSSCredential.INITIATE_ONLY);
    }

    /**
     * Acquire credentials from keytab
     */
    static GSSCredential acquireFromKeytab(String principal, String keytab, int lifetime)
            throws Exception {
        GSSManager manager = GSSManager.getInstance();

        // Verify keytab exists
        File kt = new File(keytab);
        if (!kt.exists()) {
            throw new Exception("Keytab file not found: " + keytab);
        }

        // Create the name
        GSSName name = manager.createName(principal, KRB5_PRINCIPAL_NT);

        // Create credential store with keytab
        Map<String, String> store = new HashMap<>();
        store.put("keytab", keytab);
        // For client keytab (initiator), use client_keytab
        store.put("client_keytab", keytab);

        System.out.println("Using keytab: " + keytab);
        System.out.println("Acquiring credentials for " + principal + "...");

        return manager.createCredential(
                name,
                store,
                lifetime,
                KRB5_MECH,
                GSSCredential.INITIATE_ONLY);
    }

    /**
     * Store credentials to ccache file
     */
    static void storeToCcache(GSSCredential cred, String ccacheFile)
            throws Exception {
        Map<String, String> store = new HashMap<>();
        store.put("ccache", ccacheFile);

        try {
            cred.storeInto(
                    GSSCredential.INITIATE_ONLY,
                    KRB5_MECH,
                    true,   // overwrite
                    true,   // default cred
                    store);
            System.out.println("Credentials stored to: " + ccacheFile);
        } catch (GSSException e) {
            if (e.getMajor() == GSSException.UNAVAILABLE) {
                System.err.println("Warning: storeInto() not available with Java Krb5.");
                System.err.println("Use -Dsun.security.jgss.native=true for full support.");
                System.err.println("Credentials acquired but NOT stored to ccache.");
            } else {
                throw e;
            }
        }
    }

    /**
     * Read password from console
     */
    static String readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] pwd = console.readPassword(prompt);
            return new String(pwd);
        } else {
            // Fallback for non-console (e.g., IDE)
            System.out.print(prompt);
            java.util.Scanner scanner = new java.util.Scanner(System.in);
            return scanner.nextLine();
        }
    }

    /**
     * Get the realm from a principal name
     */
    static String getRealm(String principal) {
        int at = principal.lastIndexOf('@');
        return at >= 0 ? principal.substring(at + 1) : "UNKNOWN";
    }

    /**
     * Format timestamp for display
     */
    static String formatTime(long millis) {
        java.text.SimpleDateFormat sdf =
                new java.text.SimpleDateFormat("MM/dd/yy HH:mm:ss");
        return sdf.format(new java.util.Date(millis));
    }

    /**
     * Get current user's UID (for default ccache name)
     */
    static String getUid() {
        // Try to get UID from system
        try {
            String uid = System.getProperty("user.name");
            // On Unix, we'd use getuid(), but for portability use username
            return uid != null ? uid : "0";
        } catch (Exception e) {
            return "0";
        }
    }

    static void usage(String error) {
        if (error != null) {
            System.err.println("Error: " + error);
            System.err.println();
        }
        System.err.println("Usage: java KinitTool [-k keytab] [-c ccache] [-l lifetime] principal");
        System.err.println();
        System.err.println("Options:");
        System.err.println("  -k keytab   Use keytab file for authentication");
        System.err.println("  -c ccache   Write credentials to specified ccache file");
        System.err.println("  -l lifetime Request specific lifetime in seconds");
        System.err.println("  principal   The Kerberos principal (e.g., user@REALM)");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  java KinitTool user@EXAMPLE.COM");
        System.err.println("  java KinitTool -k /etc/krb5.keytab host/server@EXAMPLE.COM");
        System.err.println("  java -Dsun.security.jgss.native=true KinitTool -c /tmp/mycc user@REALM");
        System.exit(error != null ? 1 : 0);
    }
}
