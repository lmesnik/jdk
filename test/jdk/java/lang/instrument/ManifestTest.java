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
 * @bug 6274276
 * @summary JLI JAR manifest processing should ignore leading and trailing white space.
 * @key intermittent
 * @modules java.instrument
 * @library /test/lib
 * @build ManifestTestApp ExampleForBootClassPath
 * @run main/othervm/timeout=900 ManifestTest
 */

import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.JDKToolLauncher;
import jdk.test.lib.Utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ManifestTest {

    private static final String AGENT_CLASS = "ManifestTestAgent";
    private static final String APP_CLASS = "ManifestTestApp";
    private static final String EXAMPLE_CLASS = "ExampleForBootClassPath";
    private static final String OUT_OF_THE_WAY = "out_of_the_way";
    private static final String BAD_CLASS_SUFFIX = ".bad";

    private static Path getClassPath(String className) {
        return Paths.get(Utils.TEST_CLASSES, className + ".class");
    }

    private static void compileAgent() throws Exception {
        JDKToolLauncher javac = JDKToolLauncher.create("javac")
                .addToolArg("-d")
                .addToolArg(".")
                .addToolArg(Paths.get(Utils.TEST_SRC, AGENT_CLASS + ".java").toString());
        ProcessTools.executeCommand(javac.getCommand());
    }

    private static void prepareOutOfTheWay() throws IOException {
        Path outDir = Paths.get(OUT_OF_THE_WAY);
        Files.createDirectories(outDir);

        // Move ExampleForBootClassPath.class out of the way
        Path exampleClass = getClassPath(EXAMPLE_CLASS);
        Files.move(exampleClass, outDir.resolve(EXAMPLE_CLASS + ".class"));

        // Create bad version
        String badJava = new String(Files.readAllBytes(Paths.get(Utils.TEST_SRC, EXAMPLE_CLASS + ".java")))
                .replace("return 15", "return 42");
        Path badJavaPath = outDir.resolve(EXAMPLE_CLASS + ".java" + BAD_CLASS_SUFFIX);
        Files.write(badJavaPath, badJava.getBytes());

        JDKToolLauncher javacBad = JDKToolLauncher.create("javac")
                .addToolArg(badJavaPath.toString());
        ProcessTools.executeCommand(javacBad.getCommand());

        Files.move(outDir.resolve(EXAMPLE_CLASS + ".class"), outDir.resolve(EXAMPLE_CLASS + ".class" + BAD_CLASS_SUFFIX));
    }

    private static List<String> makeAJar(String testToken) throws Exception {
        // This method replicates make_a_JAR from the shell script
        // Implement logic to create manifest and jar based on token
        // For brevity, I'll implement a switch or map for each case
        // But since there are many, group them

        Path manifest = Paths.get(AGENT_CLASS + ".mf");
        List<String> manifestLines = new ArrayList<>();
        manifestLines.add(getVersionLine(testToken));
        manifestLines.add(getPremainLine(testToken));

        String bootCpLine = getBootCpLine(testToken);
        if (!bootCpLine.isEmpty()) {
            manifestLines.add(bootCpLine);
        }

        String canRedefLine = getCanRedefLine(testToken);
        if (!canRedefLine.isEmpty()) {
            manifestLines.add(canRedefLine);
        }

        String canRetransLine = getCanRetransLine(testToken);
        if (!canRetransLine.isEmpty()) {
            manifestLines.add(canRetransLine);
        }

        String canSetNmpLine = getCanSetNmpLine(testToken);
        if (!canSetNmpLine.isEmpty()) {
            manifestLines.add(canSetNmpLine);
        }

        String expectBootCpLine = "ExampleForBootClassPath was not loaded.";
        String expectRedefLine = "isRedefineClassesSupported()=false";
        String expectRetransLine = "isRetransformClassesSupported()=false";
        String expectNmpLine = "isNativeMethodPrefixSupported()=false";
        List<String> toBeDeleted = new ArrayList<>();

        setupBootCp(testToken, Paths.get(OUT_OF_THE_WAY, EXAMPLE_CLASS + ".class"),
                    Paths.get(OUT_OF_THE_WAY, EXAMPLE_CLASS + ".class" + BAD_CLASS_SUFFIX),
                    toBeDeleted);

        if (testToken.startsWith("can_redef_line")) {
            expectRedefLine = getExpectRedef(testToken);
        }
        if (testToken.startsWith("can_retrans_line")) {
            expectRetransLine = getExpectRetrans(testToken);
        }
        if (testToken.startsWith("can_set_nmp_line")) {
            expectNmpLine = getExpectNmp(testToken);
        }
        if (testToken.startsWith("boot_cp_line")) {
            expectBootCpLine = "ExampleForBootClassPath was loaded.";
        }

        Files.write(manifest, manifestLines);

        JDKToolLauncher jar = JDKToolLauncher.create("jar")
                .addToolArg("cvfm")
                .addToolArg(AGENT_CLASS + ".jar")
                .addToolArg(AGENT_CLASS + ".mf")
                .addToolArg(AGENT_CLASS + ".class");
        ProcessTools.executeCommand(jar.getCommand());

        // Write expect files
        Files.write(Paths.get("expect_boot_cp_line"), expectBootCpLine.getBytes());
        Files.write(Paths.get("expect_redef_line"), expectRedefLine.getBytes());
        Files.write(Paths.get("expect_retrans_line"), expectRetransLine.getBytes());
        Files.write(Paths.get("expect_set_nmp_line"), expectNmpLine.getBytes());

        return toBeDeleted;
    }

    private static void runTestCase(String token) throws Throwable {
        System.out.println("===== begin test case: " + token + " =====");
        List<String> toBeDeleted = makeAJar(token);

        List<String> cmd = new ArrayList<>();
        cmd.add("-javaagent:" + AGENT_CLASS + ".jar");
        cmd.add("-classpath");
        cmd.add(Utils.TEST_CLASSES);
        cmd.add(APP_CLASS);

        OutputAnalyzer output = ProcessTools.executeTestJvm(cmd.toArray(new String[0]));
        output.shouldHaveExitValue(0);
        output.reportDiagnosticSummary();

        String mesg = "Hello from " + AGENT_CLASS + "!";
        output.shouldContain(mesg);

        String bootCpMesg = new String(Files.readAllBytes(Paths.get("expect_boot_cp_line"))).trim();
        output.shouldContain(bootCpMesg);

        String redefMesg = new String(Files.readAllBytes(Paths.get("expect_redef_line"))).trim();
        output.shouldContain(redefMesg);

        String retransMesg = new String(Files.readAllBytes(Paths.get("expect_retrans_line"))).trim();
        output.shouldContain(retransMesg);

        String nmpMesg = new String(Files.readAllBytes(Paths.get("expect_set_nmp_line"))).trim();
        output.shouldContain(nmpMesg);

        // Cleanup
        for (String dir : toBeDeleted) {
            deleteDirectory(Paths.get(dir));
        }

        System.out.println("===== end test case: " + token + " =====");
    }

    public static void main(String[] args) throws Throwable {
        prepareOutOfTheWay();
        compileAgent();

        String[] tokens = {
            "defaults",
            "version_line1",
            "version_line2",
            "version_line3",
            "premain_line1",
            "premain_line2",
            "premain_line3",
            "boot_cp_line1",
            "boot_cp_line2",
            "boot_cp_line3",
            "boot_cp_line4",
            "boot_cp_line5",
            "can_redef_line1",
            "can_redef_line2",
            "can_redef_line3",
            "can_redef_line4",
            "can_redef_line5",
            "can_redef_line6",
            "can_redef_line7",
            "can_redef_line8",
            "can_redef_line10",
            "can_redef_line11",
            "can_retrans_line1",
            "can_retrans_line2",
            "can_retrans_line3",
            "can_retrans_line4",
            "can_retrans_line5",
            "can_retrans_line6",
            "can_retrans_line7",
            "can_retrans_line8",
            "can_retrans_line10",
            "can_retrans_line11",
            "can_set_nmp_line1",
            "can_set_nmp_line2",
            "can_set_nmp_line3",
            "can_set_nmp_line4",
            "can_set_nmp_line5",
            "can_set_nmp_line6",
            "can_set_nmp_line7",
            "can_set_nmp_line8",
            "can_set_nmp_line10",
            "can_set_nmp_line11"
        };

        for (String token : tokens) {
            runTestCase(token);
        }
    }

    private static String getVersionLine(String token) {
        switch (token) {
            case "version_line1": return "Manifest-Version:  1.0";
            case "version_line2": return "Manifest-Version: 1.0 ";
            case "version_line3": return "Manifest-Version:  1.0 ";
            default: return "Manifest-Version: 1.0";
        }
    }

    private static String getPremainLine(String token) {
        String base = "Premain-Class: " + AGENT_CLASS;
        switch (token) {
            case "premain_line1": return "Premain-Class:  " + AGENT_CLASS;
            case "premain_line2": return "Premain-Class: " + AGENT_CLASS + " ";
            case "premain_line3": return "Premain-Class:  " + AGENT_CLASS + " ";
            default: return base;
        }
    }

    private static String getBootCpLine(String token) {
        switch (token) {
            case "boot_cp_line1": return "Boot-Class-Path: no_white_space";
            case "boot_cp_line2": return "Boot-Class-Path:  has_leading_blank";
            case "boot_cp_line3": return "Boot-Class-Path: has_trailing_blank ";
            case "boot_cp_line4": return "Boot-Class-Path:  has_leading_and_trailing_blank ";
            case "boot_cp_line5": return "Boot-Class-Path: has_embedded blank";
            default: return "";
        }
    }

    private static String getCanRedefLine(String token) {
        switch (token) {
            case "can_redef_line1": return "Can-Redefine-Classes: true";
            case "can_redef_line2": return "Can-Redefine-Classes:  true";
            case "can_redef_line3": return "Can-Redefine-Classes: true ";
            case "can_redef_line4": return "Can-Redefine-Classes:  true ";
            case "can_redef_line5": return "Can-Redefine-Classes: false";
            case "can_redef_line6": return "Can-Redefine-Classes:  false";
            case "can_redef_line7": return "Can-Redefine-Classes: false ";
            case "can_redef_line8": return "Can-Redefine-Classes:  false ";
            case "can_redef_line10": return "Can-Redefine-Classes: ";
            case "can_redef_line11": return "Can-Redefine-Classes:  ";
            default: return "";
        }
    }

    private static String getCanRetransLine(String token) {
        switch (token) {
            case "can_retrans_line1": return "Can-Retransform-Classes: true";
            case "can_retrans_line2": return "Can-Retransform-Classes:  true";
            case "can_retrans_line3": return "Can-Retransform-Classes: true ";
            case "can_retrans_line4": return "Can-Retransform-Classes:  true ";
            case "can_retrans_line5": return "Can-Retransform-Classes: false";
            case "can_retrans_line6": return "Can-Retransform-Classes:  false";
            case "can_retrans_line7": return "Can-Retransform-Classes: false ";
            case "can_retrans_line8": return "Can-Retransform-Classes:  false ";
            case "can_retrans_line10": return "Can-Retransform-Classes: ";
            case "can_retrans_line11": return "Can-Retransform-Classes:  ";
            default: return "";
        }
    }

    private static String getCanSetNmpLine(String token) {
        switch (token) {
            case "can_set_nmp_line1": return "Can-Set-Native-Method-Prefix: true";
            case "can_set_nmp_line2": return "Can-Set-Native-Method-Prefix:  true";
            case "can_set_nmp_line3": return "Can-Set-Native-Method-Prefix: true ";
            case "can_set_nmp_line4": return "Can-Set-Native-Method-Prefix:  true ";
            case "can_set_nmp_line5": return "Can-Set-Native-Method-Prefix: false";
            case "can_set_nmp_line6": return "Can-Set-Native-Method-Prefix:  false";
            case "can_set_nmp_line7": return "Can-Set-Native-Method-Prefix: false ";
            case "can_set_nmp_line8": return "Can-Set-Native-Method-Prefix:  false ";
            case "can_set_nmp_line10": return "Can-Set-Native-Method-Prefix: ";
            case "can_set_nmp_line11": return "Can-Set-Native-Method-Prefix:  ";
            default: return "";
        }
    }

    private static String getExpectRedef(String token) {
        if (token.endsWith("1") || token.endsWith("2") || token.endsWith("3") || token.endsWith("4")) {
            return "isRedefineClassesSupported()=true";
        } else {
            return "isRedefineClassesSupported()=false";
        }
    }

    private static String getExpectRetrans(String token) {
        if (token.endsWith("1") || token.endsWith("2") || token.endsWith("3") || token.endsWith("4")) {
            return "isRetransformClassesSupported()=true";
        } else {
            return "isRetransformClassesSupported()=false";
        }
    }

    private static String getExpectNmp(String token) {
        if (token.endsWith("1") || token.endsWith("2") || token.endsWith("3") || token.endsWith("4")) {
            return "isNativeMethodPrefixSupported()=true";
        } else {
            return "isNativeMethodPrefixSupported()=false";
        }
    }

    private static void setupBootCp(String token, Path goodClass, Path badClass, List<String> toBeDeleted) throws IOException {
        switch (token) {
            case "boot_cp_line1":
                Path noWhite = Paths.get("no_white_space");
                Files.createDirectories(noWhite);
                Files.copy(goodClass, noWhite.resolve(EXAMPLE_CLASS + ".class"));
                toBeDeleted.add("no_white_space");
                break;
            case "boot_cp_line2":
                Path leading = Paths.get("has_leading_blank");
                Path leadingBad = Paths.get(" has_leading_blank");
                Files.createDirectories(leading);
                Files.createDirectories(leadingBad);
                Files.copy(goodClass, leading.resolve(EXAMPLE_CLASS + ".class"));
                Files.copy(badClass, leadingBad.resolve(EXAMPLE_CLASS + ".class"));
                toBeDeleted.add(" has_leading_blank");
                break;
            case "boot_cp_line3":
                Path trailing = Paths.get("has_trailing_blank");
                Path trailingBad = Paths.get("has_trailing_blank ");
                Files.createDirectories(trailing);
                Files.createDirectories(trailingBad);
                Files.copy(goodClass, trailing.resolve(EXAMPLE_CLASS + ".class"));
                Files.copy(badClass, trailingBad.resolve(EXAMPLE_CLASS + ".class"));
                toBeDeleted.add("has_trailing_blank ");
                break;
            case "boot_cp_line4":
                Path both = Paths.get("has_leading_and_trailing_blank");
                Path bothBad = Paths.get(" has_leading_and_trailing_blank ");
                Files.createDirectories(both);
                Files.createDirectories(bothBad);
                Files.copy(goodClass, both.resolve(EXAMPLE_CLASS + ".class"));
                Files.copy(badClass, bothBad.resolve(EXAMPLE_CLASS + ".class"));
                toBeDeleted.add(" has_leading_and_trailing_blank ");
                break;
            case "boot_cp_line5":
                Path embedded = Paths.get("has_embedded");
                Path embeddedBad = Paths.get("has_embedded blank");
                Files.createDirectories(embedded);
                Files.createDirectories(embeddedBad);
                Files.copy(goodClass, embedded.resolve(EXAMPLE_CLASS + ".class"));
                Files.copy(badClass, embeddedBad.resolve(EXAMPLE_CLASS + ".class"));
                toBeDeleted.add("has_embedded blank");
                break;
            default:
                // no setup
        }
    }

    private static void deleteDirectory(Path dir) throws IOException {
        Files.walk(dir)
             .sorted((a, b) -> b.compareTo(a)) // reverse order to delete files first
             .forEach(p -> {
                 try {
                     Files.delete(p);
                 } catch (IOException e) {
                     throw new RuntimeException(e);
                 }
             });
    }
    }
}