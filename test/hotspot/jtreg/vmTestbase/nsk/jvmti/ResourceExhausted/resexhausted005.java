/*
 * Copyright (c) 2007, 2025, Oracle and/or its affiliates. All rights reserved.
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
package nsk.jvmti.ResourceExhausted;

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;

import nsk.share.Consts;
import nsk.share.test.Stresser;

import jdk.test.lib.compiler.InMemoryJavaCompiler;

import jtreg.SkippedException;


public class resexhausted005 {

    static final long MAX_ITERATIONS = Long.MAX_VALUE;

    public static int tmp;
    public static String genMethod(int count) {
        return "public static int compute(int a, int b) {" +
               "int x = a + b; " +
        "int y = a - b;" +
        "if (x > y) {" +
        "    x = x * 2;" +
        "} else {" +
        "    y = y * 2;" +
        "}" +
        "return x + y;" +
       "}";
    }
    public static String B(int count) {
        return new String("public class B" + count + " {" +
                genMethod(0) +
                "   public static void compiledMethod() { " +
                "   }" +
                "}");
    }

    static class MyClassLoader extends ClassLoader {
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (name.startsWith("B")) {
                int index = Integer.parseInt(name.substring(1));
                byte[] b = InMemoryJavaCompiler.compile(name, B(index));
                return defineClass(name, b, 0, b.length);
            } else {
                return super.findClass(name);
            }
        }
    };


    public static int run(String args[], PrintStream out) {
        Stresser stress = new Stresser(args);

        MyClassLoader loader = new MyClassLoader();
        Helper.resetExhaustedEvent();

        out.println("Loading classes...");
        stress.start(MAX_ITERATIONS);
        ArrayList objs = new ArrayList();
        int count = 100_000;
        try {
            int index = 0;
            while (index < 100 && Helper.getExhaustedEventFlags() == 0) {
                String name = new String("B" + index);
                Class c = loader.findClass(name);
                Object o = c.newInstance();
                objs.add(o);
                Method m = c.getMethod("compiledMethod");
                for (int i = 0; i < count; i++) {
                    m.invoke(o);
                }
                index++;
            }
            if (Helper.getExhaustedEventFlags() == 0) {
                System.out.println("Test resexhausted005: Can't fill CodeCache. Test was useless.");
                throw new SkippedException("Test did not get an OutOfMemory error");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            stress.finish();
        }

        if (!Helper.checkResult(Helper.JVMTI_RESOURCE_EXHAUSTED_OOM_ERROR, ""
                                )) {
            return Consts.TEST_FAILED;
        }

        return Consts.TEST_PASSED;
    }

    public static void main(String[] args) {
        args = nsk.share.jvmti.JVMTITest.commonInit(args);

        int result = run(args, System.out);
        System.out.println(result == Consts.TEST_PASSED ? "TEST PASSED" : "TEST FAILED");
        System.exit(result + Consts.JCK_STATUS_BASE);
    }
}
