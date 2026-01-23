/*
 * Copyright (c) 2014, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 8042796
 * @summary jvmtiRedefineClasses.cpp: guarantee(false) failed: OLD and/or OBSOLETE method(s) found
 * @modules java.instrument
 * @library /test/lib
 * @build RedefineMethodDelInvokeApp RedefineMethodDelInvokeAgent RedefineMethodDelInvokeTarget
 * @run main RedefineMethodDelInvokeTest
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

public class RedefineMethodDelInvokeTest {

    private static final String AGENT_JAR = "RedefineMethodDelInvokeAgent.jar";
    private static final String MANIFEST = "RedefineMethodDelInvokeAgent.mf";
    private static final String APP_CLASS = "RedefineMethodDelInvokeApp";

    private static void buildAgentJar() throws Exception {
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Manifest-Version: 1.0");
        manifestLines.add("Premain-Class: RedefineMethodDelInvokeAgent");
        manifestLines.add("Can-Redefine-Classes: true");
        Files.write(manifestPath, manifestLines);

        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("RedefineMethodDelInvokeAgent.class");  // Assuming compiled
        ProcessTools.executeCommand(jar.getCommand());

        Files.deleteIfExists(manifestPath);
    }

    private static void compileRedefinedClasses() throws Exception {
        // Compile version 1
        Path target1Src = Paths.get(Utils.TEST_SRC, "RedefineMethodDelInvokeTarget_1.java");
        Path target1Dest = Paths.get("RedefineMethodDelInvokeTarget.java");
        Files.copy(target1Src, target1Dest);
        JDKToolLauncher javac1 = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(target1Dest.toString());
        ProcessTools.executeCommand(javac1.getCommand());
        Files.move(Paths.get("RedefineMethodDelInvokeTarget.class"), Paths.get("RedefineMethodDelInvokeTarget_1.class"));
        Files.move(target1Dest, Paths.get("RedefineMethodDelInvokeTarget_1.java"));

        // Compile version 2
        Path target2Src = Paths.get(Utils.TEST_SRC, "RedefineMethodDelInvokeTarget_2.java");
        Path target2Dest = Paths.get("RedefineMethodDelInvokeTarget.java");
        Files.copy(target2Src, target2Dest);
        JDKToolLauncher javac2 = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(target2Dest.toString());
        ProcessTools.executeCommand(javac2.getCommand());
        Files.move(Paths.get("RedefineMethodDelInvokeTarget.class"), Paths.get("RedefineMethodDelInvokeTarget_2.class"));
        Files.move(target2Dest, Paths.get("RedefineMethodDelInvokeTarget_2.java"));
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();
        compileRedefinedClasses();

        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("-XX:+AllowRedefinitionToAddDeleteMethods");
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        int result = output.getExitValue();

        if (result != 0) {
            System.out.println("The test returned expected exit code: " + result);
        } else {
            throw new RuntimeException("FAIL: the test returned unexpected exit code: " + result);
        }

        String mesg = "Exception";
        if (output.getOutput().contains(mesg)) {
            throw new RuntimeException("FAIL: found '" + mesg + "' in the test output");
        } else {
            System.out.println("PASS: did NOT find '" + mesg + "' in the test output");
        }
    }
}