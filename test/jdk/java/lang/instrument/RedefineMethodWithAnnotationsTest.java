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
 * @bug 7022100
 * @summary Method annotations are incorrectly set when redefining classes.
 * @modules java.instrument
 * @library /test/lib
 * @build RedefineMethodWithAnnotationsTarget RedefineMethodWithAnnotationsApp RedefineMethodWithAnnotationsAnnotations RedefineMethodWithAnnotationsAgent
 * @run main RedefineMethodWithAnnotationsTest
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

public class RedefineMethodWithAnnotationsTest {

    private static final String AGENT_JAR = "RedefineMethodWithAnnotationsAgent.jar";
    private static final String MANIFEST = "RedefineMethodWithAnnotationsAgent.mf";
    private static final String APP_CLASS = "RedefineMethodWithAnnotationsApp";

    private static void buildAgentJar() throws Exception {
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Manifest-Version: 1.0");
        manifestLines.add("Premain-Class: RedefineMethodWithAnnotationsAgent");
        manifestLines.add("Can-Redefine-Classes: true");
        Files.write(manifestPath, manifestLines);

        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("RedefineMethodWithAnnotationsAgent.class");  // Assuming compiled
        ProcessTools.executeCommand(jar.getCommand());

        Files.deleteIfExists(manifestPath);
    }

    private static void compileRedefinedClasses() throws Exception {
        // Copy and compile RedefineMethodWithAnnotationsTarget_2.java
        Path targetSrc = Paths.get(Utils.TEST_SRC, "RedefineMethodWithAnnotationsTarget_2.java");
        Path targetDest = Paths.get("RedefineMethodWithAnnotationsTarget.java");
        Files.copy(targetSrc, targetDest);

        // Copy RedefineMethodWithAnnotationsAnnotations.java
        Path annSrc = Paths.get(Utils.TEST_SRC, "RedefineMethodWithAnnotationsAnnotations.java");
        Path annDest = Paths.get("RedefineMethodWithAnnotationsAnnotations.java");
        Files.copy(annSrc, annDest);

        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(targetDest.toString())
                .addToolArg(annDest.toString());
        ProcessTools.executeCommand(javac.getCommand());
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();
        compileRedefinedClasses();

        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("-XX:+UnlockDiagnosticVMOptions");
        cmd.add("-XX:+StressLdcRewrite");
        cmd.add("-XX:+IgnoreUnrecognizedVMOptions");
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        int result = output.getExitValue();

        if (result != 0) {
            throw new RuntimeException("The run failed with exit code " + result);
        }

        String mesg = "Exception|fatal";
        if (output.getOutput().matches("(?s).*" + mesg + ".*")) {
            throw new RuntimeException("FAIL: found '" + mesg + "' in the test output");
        } else {
            System.out.println("PASS: did NOT find '" + mesg + "' in the test output");
        }
    }
}