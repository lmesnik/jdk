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
 * @bug 6572160
 * @summary stress getObjectSize() API
 * @modules java.instrument
 * @library /test/lib
 * @build StressGetObjectSizeApp
 * @run main/othervm StressGetObjectSizeTest
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

public class StressGetObjectSizeTest {

    private static final String AGENT_JAR = "basicAgent.jar";
    private static final String INSTRUMENTATION_HANDOFF = "InstrumentationHandoff";
    private static final String MANIFEST = "basicAgent.mf";
    private static final String APP_CLASS = "StressGetObjectSizeApp";

    private static void buildAgentJar() throws Exception {
        // Copy InstrumentationHandoff.java from TESTSRC
        Path handoffSrc = Paths.get(Utils.TEST_SRC, INSTRUMENTATION_HANDOFF + ".java");
        Path handoffDest = Paths.get(INSTRUMENTATION_HANDOFF + ".java");
        Files.copy(handoffSrc, handoffDest);

        // Compile it
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-g")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(handoffDest.toString());
        ProcessTools.executeCommand(javac.getCommand());

        // Copy manifest from TESTSRC
        Path manifestSrc = Paths.get(Utils.TEST_SRC, MANIFEST);
        Path manifestDest = Paths.get(MANIFEST);
        Files.copy(manifestSrc, manifestDest);

        // Create jar
        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg(INSTRUMENTATION_HANDOFF + ".class");
        ProcessTools.executeCommand(jar.getCommand());

        // Cleanup
        Files.deleteIfExists(handoffDest);
        Files.deleteIfExists(Paths.get(INSTRUMENTATION_HANDOFF + ".class"));
        Files.deleteIfExists(manifestDest);
    }

    public static void main(String[] args) throws Exception {
        buildAgentJar();

        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);
        cmd.add(APP_CLASS);  // The app takes its own class name as arg

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();

        String mesg = "ASSERTION FAILED";
        if (output.getOutput().contains(mesg)) {
            throw new RuntimeException("FAIL: found '" + mesg + "' in the test output");
        } else {
            System.out.println("PASS: did NOT find '" + mesg + "' in the test output");
        }
    }
}