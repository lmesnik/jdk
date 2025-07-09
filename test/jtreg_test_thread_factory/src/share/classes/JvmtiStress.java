/*
 * Copyright (c) 2022, 2023, Oracle and/or its affiliates. All rights reserved.
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

import java.util.concurrent.ThreadFactory;

public class JvmtiStress implements ThreadFactory {

    static {
        // This property is used by ProcessTools and some tests
        try {
            System.setProperty("test.thread.factory", "Virtual");
        } catch (Throwable t) {
            // might be thrown by security manager
        }
    }

    private native void startIteration();

    private native JvmtiStatistics finishIteration();

    static final ThreadFactory VIRTUAL_TF = Thread.ofPlatform().factory();

    @Override
    public Thread newThread(Runnable task) {
        return VIRTUAL_TF.newThread(task);
    }

}

class JvmtiStatistics {
    public long cbBreakpoint;
    public long cbClassFileLoadHook;
    public long cbClassLoad;
    public long cbClassPrepare;
    public long cbCompiledMethodLoad;
    public long cbCompiledMethodUnload;
    public long cbDataDumpRequest;
    public long cbDynamicCodeGenerated;
    public long cbException;
    public long cbExceptionCatch;
    public long cbFieldAccess;
    public long cbFieldModification;
    public long cbFramePop;
    public long cbGarbageCollectionFinish;
    public long cbGarbageCollectionStart;
    public long cbMethodEntry;
    public long cbMethodExit;
    public long cbMonitorContendedEnter;
    public long cbMonitorContendedEntered;
    public long cbMonitorWait;
    public long cbMonitorWaited;
    public long cbNativeMethodBind;
    public long cbObjectFree;
    public long cbResourceExhausted;
    public long cbSampledObjectAlloc;
    public long cbSingleStep;
    public long cbThreadEnd;
    public long cbThreadStart;
    public long cbVMDeath;
    public long cbVMInit;
    public long cbVMObjectAlloc;

    public long stringObjects;
    public long totalObjects;

    public long inspectedMethods;
    public long inspectedVariables;

    public long earlyReturns;
    public long poppedFrames;
}

