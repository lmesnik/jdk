/*
 * Copyright (c) 2013, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 7182152 8007935
 * @summary Redefine a subclass that implements two interfaces and verify that the right methods are called.
 * @modules java.instrument
 * @library /test/lib
 * @build RedefineSubclassWithTwoInterfacesApp RedefineSubclassWithTwoInterfacesAgent RedefineSubclassWithTwoInterfacesTarget RedefineSubclassWithTwoInterfacesImpl RedefineSubclassWithTwoInterfacesIntf1 RedefineSubclassWithTwoInterfacesIntf2 RedefineSubclassWithTwoInterfacesRemote
 * @run main RedefineSubclassWithTwoInterfacesTest
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

public class RedefineSubclassWithTwoInterfacesTest {

    private static final String AGENT_JAR = "RedefineSubclassWithTwoInterfacesAgent.jar";
    private static final String MANIFEST = "RedefineSubclassWithTwoInterfacesAgent.mf";
    private static final String APP_CLASS = "RedefineSubclassWithTwoInterfacesApp";

    private static void buildAgentJar() throws Exception {
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Manifest-Version: 1.0");
        manifestLines.add("Premain-Class: RedefineSubclassWithTwoInterfacesAgent");
        manifestLines.add("Can-Redefine-Classes: true");
        Files.write(manifestPath, manifestLines);

        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("RedefineSubclassWithTwoInterfacesAgent.class");  // Assuming compiled
        ProcessTools.executeCommand(jar.getCommand());

        Files.deleteIfExists(manifestPath);
    }

    private static void compileReplacementClasses() throws Exception {
        // Copy and compile replacement classes
        Path targetSrc = Paths.get(Utils.TEST_SRC, "RedefineSubclassWithTwoInterfacesTarget_1.java");
        Path targetDest = Paths.get("RedefineSubclassWithTwoInterfacesTarget.java");
        Files.copy(targetSrc, targetDest);

        Path implSrc = Paths.get(Utils.TEST_SRC, "RedefineSubclassWithTwoInterfacesImpl_1.java");
        Path implDest = Paths.get("RedefineSubclassWithTwoInterfacesImpl.java");
        Files.copy(implSrc, implDest);

        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-cp")
                .addToolArg(Utils.TEST_CLASSES)
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(targetDest.toString())
                .addToolArg(implDest.toString());
        ProcessTools.executeCommand(javac.getCommand());

        // Move originals aside if needed, but script renames them
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();
        compileReplacementClasses();

        List<String> cmd = new ArrayList<>();
        cmd.add("-Xlog:redefine+class+load=trace,redefine+class+load+exceptions=trace,redefine+class+timer=trace,redefine+class+obsolete=trace,redefine+class+obsolete+metadata=trace,redefine+class+constantpool=trace");
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        int result = output.getExitValue();

        if (result != 0) {
            throw new RuntimeException("RedefineSubclassWithTwoInterfacesApp failed.");
        }

        String failMesg = "guarantee";
        if (output.getOutput().contains(failMesg)) {
            throw new RuntimeException("FAIL: found '" + failMesg + "' in the test output");
        }

        String pass1Mesg = "before any redefines";
        long cnt1 = output.asLines().stream().filter(line -> line.contains(pass1Mesg) && line.contains("version-0")).count();
        if (cnt1 == 2) {
            System.out.println("INFO: found 2 version-0 '" + pass1Mesg + "' mesgs.");
        } else {
            throw new RuntimeException("FAIL: did NOT find 2 version-0 '" + pass1Mesg + "' mesgs.");
        }

        String pass2Mesg = "after redefine";
        long cnt2 = output.asLines().stream().filter(line -> line.contains(pass2Mesg) && line.contains("version-1")).count();
        if (cnt2 == 2) {
            System.out.println("INFO: found 2 version-1 '" + pass2Mesg + "' mesgs.");
        } else {
            throw new RuntimeException("FAIL: did NOT find 2 version-1 '" + pass2Mesg + "' mesgs.");
        }

        System.out.println("PASS: test passed both positive and negative output checks.");
    }
}