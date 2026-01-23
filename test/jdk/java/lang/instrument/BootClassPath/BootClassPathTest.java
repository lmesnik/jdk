/*
 * Copyright (c) 2004, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 5055293 8273188
 * @summary Test non US-ASCII characters in the value of the Boot-Class-Path attribute.
 * @key intermittent
 * @modules java.instrument
 * @library /test/lib
 * @build BootClassPath.Agent BootClassPath.DummyMain BootClassPath.AgentSupport BootClassPath.Setup BootClassPath.Cleanup
 * @run main/othervm/timeout=240 BootClassPath.BootClassPathTest
 */

package BootClassPath;

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

public class BootClassPathTest {

    private static final String AGENT_JAR = "Agent.jar";
    private static final String MANIFEST = "MANIFEST.MF";

    public static void main(String[] args) throws Exception {
        // Compile Setup
        compile("Setup.java");

        // Run Setup to create boot.dir
        List<String> setupCmd = new ArrayList<>();
        setupCmd.add("-classpath");
        setupCmd.add(Utils.TEST_CLASSES);
        setupCmd.add("Setup");
        setupCmd.add(Utils.TEST_CLASSES);
        setupCmd.add("Agent");
        setupCmd.add("");  // Empty for non-CYGWIN
        OutputAnalyzer setupOutput = ProcessTools.executeTestJvm(setupCmd.toArray(new String[0]));
        setupOutput.shouldHaveExitValue(0);
        String bootDirStr = setupOutput.getOutput().trim();  // Assuming Setup prints the boot dir
        Path bootDir = Paths.get(bootDirStr);

        // Compile test classes
        compile("Agent.java");
        compile("DummyMain.java");
        compileToDir(bootDir, "AgentSupport.java");

        // Create manifest if needed, but from script, it's output by Setup?
        // Assuming MANIFEST is created by Setup or copy from TESTSRC
        Path manifestSrc = Paths.get(Utils.TEST_SRC, "BootClassPath", MANIFEST);
        Path manifestDest = Paths.get(Utils.TEST_CLASSES, MANIFEST);
        Files.copy(manifestSrc, manifestDest);

        // Create agent jar
        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(Paths.get(Utils.TEST_CLASSES, AGENT_JAR).toString())
                .addToolArg(manifestDest.toString())
                .addToolArg("-C")
                .addToolArg(Utils.TEST_CLASSES)
                .addToolArg("Agent.class");
        ProcessTools.executeCommand(jar.getCommand());

        // Run test
        List<String> testCmd = new ArrayList<>();
        testCmd.add("-javaagent:" + Paths.get(Utils.TEST_CLASSES, AGENT_JAR).toString());
        testCmd.add("-classpath");
        testCmd.add(Utils.TEST_CLASSES);
        testCmd.add("DummyMain");
        OutputAnalyzer testOutput = ProcessTools.executeTestJvm(testCmd.toArray(new String[0]));
        int result = testOutput.getExitValue();

        // Compile Cleanup
        compile("Cleanup.java");

        // Run Cleanup
        List<String> cleanupCmd = new ArrayList<>();
        cleanupCmd.add("-classpath");
        cleanupCmd.add(Utils.TEST_CLASSES);
        cleanupCmd.add("Cleanup");
        cleanupCmd.add(bootDirStr);
        ProcessTools.executeTestJvm(cleanupCmd.toArray(new String[0]));

        if (result != 0) {
            throw new RuntimeException("Test failed with exit code " + result);
        }
    }

    private static void compile(String file) throws Exception {
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(Utils.TEST_CLASSES)
                .addToolArg(Paths.get(Utils.TEST_SRC, "BootClassPath", file).toString());
        ProcessTools.executeCommand(javac.getCommand());
    }

    private static void compileToDir(Path dir, String file) throws Exception {
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(dir.toString())
                .addToolArg(Paths.get(Utils.TEST_SRC, "BootClassPath", file).toString());
        ProcessTools.executeCommand(javac.getCommand());
    }
}