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

/*
 * @test
 * @bug 8999999
 * @summary Test GssLoginModule for acquiring GSS credentials via JAAS
 * @library /test/lib
 * @modules jdk.security.auth
 *          java.security.jgss
 * @compile -XDignore.symbol.file GssLoginModuleTest.java
 * @run main jdk.test.lib.FileInstaller TestHosts TestHosts
 * @run main/othervm -Djdk.net.hosts.file=TestHosts GssLoginModuleTest
 */

import com.sun.security.auth.module.GssLoginModule;
import org.ietf.jgss.*;
import sun.security.jgss.GSSUtil;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Test for GssLoginModule - authenticates using GSS-API credentials
 * acquired via keytab or credential cache, similar to how Krb5LoginModule
 * tests work but using the mechanism-agnostic GssLoginModule.
 */
public class GssLoginModuleTest {

    public static void main(String[] args) throws Exception {
        // Start KDC and create keytab
        new OneKDC(null);

        System.out.println("=== Test 1: Client with keytab ===");
        testClientWithKeytab();

        System.out.println("\n=== Test 2: Server with keytab ===");
        testServerWithKeytab();

        System.out.println("\n=== Test 3: Full handshake with GssLoginModule ===");
        testFullHandshake();

        System.out.println("\n=== Test 4: Initiator and Acceptor credentials ===");
        testInitiateAndAccept();

        System.out.println("\nAll tests passed!");
    }

    /**
     * Test acquiring initiator credentials using GssLoginModule with keytab
     */
    static void testClientWithKeytab() throws Exception {
        Subject subject = new Subject();
        GssLoginModule glm = new GssLoginModule();

        Map<String, String> options = new HashMap<>();
        options.put("debug", "true");
        options.put("keyTab", OneKDC.KTAB);
        options.put("name", OneKDC.USER + "@" + OneKDC.REALM);
        options.put("initiate", "true");
        options.put("doNotPrompt", "true");

        glm.initialize(subject, null, new HashMap<>(), options);
        glm.login();
        glm.commit();

        // Verify credentials were added to subject
        verifySubjectHasGSSCredentials(subject, true, false);

        System.out.println("Client keytab test passed");
    }

    /**
     * Test acquiring acceptor credentials using GssLoginModule with keytab
     */
    static void testServerWithKeytab() throws Exception {
        Subject subject = new Subject();
        GssLoginModule glm = new GssLoginModule();

        Map<String, String> options = new HashMap<>();
        options.put("debug", "true");
        options.put("keyTab", OneKDC.KTAB);
        options.put("name", OneKDC.SERVER);
        options.put("nametype", "hostbased");
        options.put("accept", "true");
        options.put("initiate", "false");
        options.put("doNotPrompt", "true");

        glm.initialize(subject, null, new HashMap<>(), options);
        glm.login();
        glm.commit();

        // Verify credentials were added to subject
        verifySubjectHasGSSCredentials(subject, false, true);

        System.out.println("Server keytab test passed");
    }

    /**
     * Test full GSS handshake using credentials from GssLoginModule
     */
    static void testFullHandshake() throws Exception {
        // Create client subject with initiator credentials
        Subject clientSubject = new Subject();
        {
            GssLoginModule glm = new GssLoginModule();
            Map<String, String> options = new HashMap<>();
            options.put("debug", "true");
            options.put("keyTab", OneKDC.KTAB);
            options.put("name", OneKDC.USER + "@" + OneKDC.REALM);
            options.put("initiate", "true");
            options.put("doNotPrompt", "true");
            glm.initialize(clientSubject, null, new HashMap<>(), options);
            glm.login();
            glm.commit();
        }

        // Create server subject with acceptor credentials
        Subject serverSubject = new Subject();
        {
            GssLoginModule glm = new GssLoginModule();
            Map<String, String> options = new HashMap<>();
            options.put("debug", "true");
            options.put("keyTab", OneKDC.KTAB);
            options.put("name", OneKDC.SERVER);
            options.put("nametype", "hostbased");
            options.put("accept", "true");
            options.put("initiate", "false");
            options.put("doNotPrompt", "true");
            glm.initialize(serverSubject, null, new HashMap<>(), options);
            glm.login();
            glm.commit();
        }

        // Get the credentials from subjects
        GSSCredential clientCred = getCredential(clientSubject, GSSCredential.INITIATE_ONLY);
        GSSCredential serverCred = getCredential(serverSubject, GSSCredential.ACCEPT_ONLY);

        if (clientCred == null) {
            throw new Exception("No initiator credential in client subject");
        }
        if (serverCred == null) {
            throw new Exception("No acceptor credential in server subject");
        }

        // Perform handshake
        GSSManager manager = GSSManager.getInstance();
        GSSName serverName = manager.createName(OneKDC.SERVER, GSSName.NT_HOSTBASED_SERVICE);

        GSSContext clientContext = Subject.callAs(clientSubject, () -> {
            GSSContext ctx = manager.createContext(
                    serverName,
                    GSSUtil.GSS_KRB5_MECH_OID,
                    clientCred,
                    GSSContext.DEFAULT_LIFETIME);
            ctx.requestMutualAuth(true);
            return ctx;
        });

        GSSContext serverContext = Subject.callAs(serverSubject, () ->
                manager.createContext(serverCred));

        // Handshake loop
        byte[] token = new byte[0];
        while (!clientContext.isEstablished() || !serverContext.isEstablished()) {
            final byte[] inToken = token;
            if (!clientContext.isEstablished()) {
                token = Subject.callAs(clientSubject, () ->
                        clientContext.initSecContext(inToken, 0, inToken.length));
            }
            if (token != null && !serverContext.isEstablished()) {
                final byte[] inToken2 = token;
                token = Subject.callAs(serverSubject, () ->
                        serverContext.acceptSecContext(inToken2, 0, inToken2.length));
            }
            if (clientContext.isEstablished() && serverContext.isEstablished()) {
                break;
            }
        }

        System.out.println("Client source: " + clientContext.getSrcName());
        System.out.println("Server target: " + serverContext.getTargName());

        // Test message exchange
        byte[] message = "Hello from GssLoginModule test!".getBytes();
        MessageProp prop = new MessageProp(0, true);

        final byte[] msgToWrap = message;
        byte[] wrapped = Subject.callAs(clientSubject, () ->
                clientContext.wrap(msgToWrap, 0, msgToWrap.length, prop));

        MessageProp prop2 = new MessageProp(0, true);
        byte[] unwrapped = Subject.callAs(serverSubject, () ->
                serverContext.unwrap(wrapped, 0, wrapped.length, prop2));

        if (!java.util.Arrays.equals(message, unwrapped)) {
            throw new Exception("Message mismatch after wrap/unwrap");
        }

        clientContext.dispose();
        serverContext.dispose();

        System.out.println("Full handshake test passed");
    }

    /**
     * Test acquiring both initiator and acceptor credentials
     */
    static void testInitiateAndAccept() throws Exception {
        Subject subject = new Subject();
        GssLoginModule glm = new GssLoginModule();

        Map<String, String> options = new HashMap<>();
        options.put("debug", "true");
        options.put("keyTab", OneKDC.KTAB);
        options.put("name", OneKDC.SERVER);
        options.put("nametype", "hostbased");
        options.put("initiate", "true");
        options.put("accept", "true");
        options.put("doNotPrompt", "true");

        glm.initialize(subject, null, new HashMap<>(), options);
        glm.login();
        glm.commit();

        // Verify both types of credentials
        verifySubjectHasGSSCredentials(subject, true, true);

        System.out.println("Initiate and Accept test passed");
    }

    /**
     * Verify that the subject contains GSSCredential(s)
     */
    static void verifySubjectHasGSSCredentials(Subject subject,
                                                boolean expectInitiator,
                                                boolean expectAcceptor) throws Exception {
        Set<GSSCredential> creds = subject.getPrivateCredentials(GSSCredential.class);
        if (creds.isEmpty()) {
            throw new Exception("No GSSCredential in subject");
        }

        boolean hasInitiator = false;
        boolean hasAcceptor = false;

        for (GSSCredential cred : creds) {
            int usage = cred.getUsage();
            System.out.println("Found credential: " + cred.getName() + " usage=" + usage);
            if (usage == GSSCredential.INITIATE_ONLY || usage == GSSCredential.INITIATE_AND_ACCEPT) {
                hasInitiator = true;
            }
            if (usage == GSSCredential.ACCEPT_ONLY || usage == GSSCredential.INITIATE_AND_ACCEPT) {
                hasAcceptor = true;
            }
        }

        if (expectInitiator && !hasInitiator) {
            throw new Exception("Expected initiator credential not found");
        }
        if (expectAcceptor && !hasAcceptor) {
            throw new Exception("Expected acceptor credential not found");
        }

        // Also check that GSSName was added as principal
        Set<Principal> principals = subject.getPrincipals();
        boolean hasGSSName = false;
        for (Principal p : principals) {
            System.out.println("Principal: " + p.getClass().getName() + " = " + p);
            if (p instanceof GSSName) {
                hasGSSName = true;
            }
        }
        if (!hasGSSName) {
            throw new Exception("GSSName not added as principal");
        }
    }

    /**
     * Get a credential from subject matching the usage type
     */
    static GSSCredential getCredential(Subject subject, int usage) throws GSSException {
        Set<GSSCredential> creds = subject.getPrivateCredentials(GSSCredential.class);
        for (GSSCredential cred : creds) {
            int credUsage = cred.getUsage();
            if (credUsage == usage || credUsage == GSSCredential.INITIATE_AND_ACCEPT) {
                return cred;
            }
        }
        return null;
    }
}
