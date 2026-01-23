/*
 * Copyright (c) 2011, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 7121600 8016838
 * @summary Redefine a big class.
 * @key intermittent
 * @modules java.instrument
 *          java.management
 * @library /test/lib
 * @build BigClass RedefineBigClassApp NMTHelper
 * @run main/othervm/timeout=600 RedefineBigClassTest
 */

import jdk.test.lib.JDKToolLauncher;
import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.Utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class RedefineBigClassTest {

    private static final String AGENT_JAR = "RedefineBigClassAgent.jar";
    private static final String MANIFEST = "RedefineBigClassAgent.mf";
    private static final String APP_CLASS = "RedefineBigClassApp";

    private static void buildAgentJar() throws Exception {
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Manifest-Version: 1.0");
        manifestLines.add("Premain-Class: RedefineBigClassAgent");
        manifestLines.add("Can-Redefine-Classes: true");
        Files.write(manifestPath, manifestLines);

        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("BigClass.class");  // Assuming BigClass is compiled
        ProcessTools.executeCommand(jar.getCommand());

        Files.deleteIfExists(manifestPath);
    }

    private static String getNMTFlag() throws Exception {
        try {
            ProcessTools.executeTestJvm("-XX:NativeMemoryTracking=detail", "-version")
                    .shouldHaveExitValue(0);
            return "-XX:NativeMemoryTracking=detail";
        } catch (Throwable t) {
            return "-XX:NativeMemoryTracking=summary";
        }
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();

        String nmt = getNMTFlag();

        List<String> cmd = new ArrayList<>();
        cmd.add("-Xlog:redefine+class+load=debug,redefine+class+load+exceptions=info");
        cmd.add(nmt);
        cmd.add("-javaagent:" + AGENT_JAR + "=BigClass.class");
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        int result = output.getExitValue();

        if (result != 0) {
            throw new RuntimeException("RedefineBigClassApp exited with status of " + result);
        }

        String mesg = "Exception";
        if (output.getOutput().contains(mesg)) {
            throw new RuntimeException("FAIL: found '" + mesg + "' in the test output");
        } else {
            System.out.println("PASS: did NOT find '" + mesg + "' in the test output");
        }
    }
}