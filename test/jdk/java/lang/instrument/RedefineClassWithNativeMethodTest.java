/*
 * Copyright (c) 2008, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 5003341 4917140 6545149
 * @summary Redefine a class with a native method.
 * @modules java.instrument
 * @library /test/lib
 * @build RedefineClassWithNativeMethodApp
 * @run main RedefineClassWithNativeMethodTest
 */

import jdk.test.lib.JDKToolLauncher;
import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.Utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class RedefineClassWithNativeMethodTest {

    private static final String AGENT_JAR = "RedefineClassWithNativeMethodAgent.jar";
    private static final String MANIFEST = "RedefineClassWithNativeMethodAgent.mf";
    private static final String AGENT_CLASS = "RedefineClassWithNativeMethodAgent";
    private static final String APP_CLASS = "RedefineClassWithNativeMethodApp";

    private static void buildAgentJar() throws Exception {
        // Assuming the agent class needs to be compiled, but if it's pre-built, skip.
        // For completeness, compile it.
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(Paths.get(Utils.TEST_SRC, AGENT_CLASS + ".java").toString());
        ProcessTools.executeCommand(javac.getCommand());

        // Create manifest
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Manifest-Version: 1.0");
        manifestLines.add("Premain-Class: " + AGENT_CLASS);
        manifestLines.add("Can-Redefine-Classes: true");
        Files.write(manifestPath, manifestLines);

        // Create jar
        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg(AGENT_CLASS + ".class");
        ProcessTools.executeCommand(jar.getCommand());

        // Cleanup
        Files.deleteIfExists(manifestPath);
        Files.deleteIfExists(Paths.get(AGENT_CLASS + ".class"));
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();

        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_JAR + "=java/lang/Thread.class");
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        int result = output.getExitValue();

        if (result != 0) {
            throw new RuntimeException("RedefineClassWithNativeMethodApp exited with status of " + result);
        }

        String mesg = "Exception";
        if (output.getOutput().contains(mesg)) {
            throw new RuntimeException("FAIL: found '" + mesg + "' in the test output");
        } else {
            System.out.println("PASS: did NOT find '" + mesg + "' in the test output");
        }
    }
}