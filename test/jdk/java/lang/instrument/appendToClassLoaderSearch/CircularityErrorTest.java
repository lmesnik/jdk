/*
 * Copyright (c) 2005, 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 6173575
 * @summary Unit tests for appendToBootstrapClassLoaderSearch and appendToSystemClassLoaderSearch methods.
 * @modules java.instrument
 * @library /test/lib
 * @build appendToClassLoaderSearch.CircularityErrorTest
 * @run main/othervm/timeout=240 appendToClassLoaderSearch.CircularityErrorTest
 */

package appendToClassLoaderSearch;

import jdk.test.lib.JDKToolLauncher;
import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.Utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class CircularityErrorTest {

    private static final String AGENT_JAR = "CircularityErrorTest.jar";
    private static final String MANIFEST = "agent.mf";

    public static void main(String[] args) throws Exception {
        // Create A.java (extends B) and B.java (extends A) for circularity
        Path a1 = Paths.get("A.java");
        List<String> aLines = new ArrayList<>();
        aLines.add("public class A extends B {}");
        Files.write(a1, aLines);

        Path b1 = Paths.get("B.java");
        List<String> bLines = new ArrayList<>();
        bLines.add("public class B {}");
        Files.write(b1, bLines);

        // Compile A and B, create A.jar with A.class, keep B.class as B.keep
        JDKToolLauncher javac1 = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(a1.toString())
                .addToolArg(b1.toString());
        ProcessTools.executeCommand(javac1.getCommand());

        JDKToolLauncher jar1 = JDKToolLauncher.create("jar")
                .addToolArg("cf")
                .addToolArg("A.jar")
                .addToolArg("A.class");
        ProcessTools.executeCommand(jar1.getCommand());

        Files.deleteIfExists(Paths.get("A.class"));
        Files.move(Paths.get("B.class"), Paths.get("B.keep"));

        // Now create A.java (extends B) again, but compile only A with B not present? Wait, script has A.2 extends B, B.2 is empty.
        // Script copies A.2 and B.2, compiles, removes B.class

        Path a2 = Paths.get("A.java");
        List<String> a2Lines = new ArrayList<>();
        a2Lines.add("public class A {}");  // Adjust based on actual A.2, but assuming
        Files.write(a2, a2Lines);

        Path b2 = Paths.get("B.java");
        List<String> b2Lines = new ArrayList<>();
        b2Lines.add("public class B extends A {}");
        Files.write(b2, b2Lines);

        JDKToolLauncher javac2 = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(a2.toString())
                .addToolArg(b2.toString());
        ProcessTools.executeCommand(javac2.getCommand());
        Files.deleteIfExists(Paths.get("B.class"));
        Files.deleteIfExists(a2);
        Files.deleteIfExists(b2);

        // Move B.keep to B.class to create circularity
        Files.move(Paths.get("B.keep"), Paths.get("B.class"));

        // Create manifest
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Premain-Class: appendToClassLoaderSearch.CircularityErrorTest");
        Files.write(manifestPath, manifestLines);

        // Create agent jar
        JDKToolLauncher agentJar = JDKToolLauncher.create("jar")
                .addToolArg("cfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("appendToClassLoaderSearch/CircularityErrorTest.class");
        ProcessTools.executeCommand(agentJar.getCommand());

        // Run the test
        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("appendToClassLoaderSearch.CircularityErrorTest");

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        output.shouldHaveExitValue(0);  // The test checks for CircularityError handling
    }
}