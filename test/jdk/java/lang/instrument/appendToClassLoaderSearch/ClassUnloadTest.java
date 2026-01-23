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
 * @build appendToClassLoaderSearch.ClassUnloadTest
 * @run main/othervm appendToClassLoaderSearch.ClassUnloadTest
 */

package appendToClassLoaderSearch;

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

public class ClassUnloadTest {

    private static final String OTHER_DIR = "other";
    private static final String AGENT_JAR = "ClassUnloadTest.jar";
    private static final String MANIFEST = "agent.mf";
    private static final String FOO = "Foo.java";
    private static final String BAR = "Bar.java";
    private static final String BAR_JAR = "Bar.jar";

    public static void main(String[] args) throws Exception {
        Path otherDir = Paths.get(Utils.TEST_CLASSES, OTHER_DIR);
        Files.createDirectories(otherDir);

        // Write Foo.java
        List<String> fooLines = new ArrayList<>();
        fooLines.add("public class Foo {");
        fooLines.add("    public static boolean doSomething() {");
        fooLines.add("        try {");
        fooLines.add("            Bar b = new Bar();");
        fooLines.add("            return true;");
        fooLines.add("        } catch (NoClassDefFoundError x) {");
        fooLines.add("            return false;");
        fooLines.add("        }");
        fooLines.add("    }");
        fooLines.add("}");
        Files.write(otherDir.resolve(FOO), fooLines);

        // Write Bar.java
        List<String> barLines = new ArrayList<>();
        barLines.add("public class Bar { }");
        Files.write(otherDir.resolve(BAR), barLines);

        // Compile Foo and Bar
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(otherDir.toString())
                .addToolArg(otherDir.resolve(FOO).toString())
                .addToolArg(otherDir.resolve(BAR).toString());
        ProcessTools.executeCommand(javac.getCommand());

        // Create Bar.jar and remove Bar.class
        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cf")
                .addToolArg(otherDir.resolve(BAR_JAR).toString())
                .addToolArg("Bar.class");
        ProcessTools.executeCommand(jar.getCommand(), otherDir.toString());
        Files.delete(otherDir.resolve("Bar.class"));

        // Create manifest for agent
        Path manifestPath = Paths.get(MANIFEST);
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add("Premain-Class: appendToClassLoaderSearch.ClassUnloadTest");
        Files.write(manifestPath, manifestLines);

        // Create agent jar
        JDKToolLauncher agentJar = JDKToolLauncher.create("jar")
                .addToolArg("cfm")
                .addToolArg(AGENT_JAR)
                .addToolArg(MANIFEST)
                .addToolArg("-C")
                .addToolArg(Utils.TEST_CLASSES)
                .addToolArg("appendToClassLoaderSearch/ClassUnloadTest.class");
        ProcessTools.executeCommand(agentJar.getCommand());

        // Run the test
        List<String> cmd = new ArrayList<>();
        cmd.add("-Xlog:class+unload");
        cmd.add("-javaagent:" + AGENT_JAR);
        cmd.add("appendToClassLoaderSearch.ClassUnloadTest");
        cmd.add(otherDir.toString());
        cmd.add(BAR_JAR);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.reportDiagnosticSummary();
        output.shouldHaveExitValue(0);  // Assuming the test passes if exit 0 and proper unloading
    }
}