/*
 * Copyright (c) 2018, 2025, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

#include <stddef.h>

#include "jvmti.h"
#include "jvmti_common.hpp"


// This prefix is used to select suspending threads by tracer/debugger
#define JVMTI_PREFIX "Jvmti"

#define JVMTI_AGENT_NAME "JvmtiStressAgent"

#define JVMTI_STATISTICS  "JvmtiStatistics"

typedef struct {
  volatile jboolean initialized;

  /* Monitor and flags to synchronize job completion between jvmti agent and other parts.*/
  jrawMonitorID finished_lock;
  volatile jboolean agent_request_stop;
  volatile jboolean agent;


  /* Settings from kitchensink properties file */
  jboolean is_debugger_enabled;
  jlong debugger_interval;
  jboolean are_events_enabled;
  jint heap_sampling_interval;
  jint frequent_events_interval;
  jint debugger_watch_methods;
  jint* events_excluded;
  jsize events_excluded_size;

  /* Event statistics */
  jrawMonitorID events_lock; /* Monitor to register events and reset/read them */
  jlong cbBreakpoint;
  jlong cbClassFileLoadHook;
  jlong cbClassLoad;
  jlong cbClassPrepare;
  jlong cbCompiledMethodLoad;
  jlong cbCompiledMethodUnload;
  jlong cbDataDumpRequest;
  jlong cbDynamicCodeGenerated;
  jlong cbException;
  jlong cbExceptionCatch;
  jlong cbFieldAccess;
  jlong cbFieldModification;
  jlong cbFramePop;
  jlong cbGarbageCollectionFinish;
  jlong cbGarbageCollectionStart;
  jlong cbMethodEntry;
  jlong cbMethodExit;
  jlong cbMonitorContendedEnter;
  jlong cbMonitorContendedEntered;
  jlong cbMonitorWait;
  jlong cbMonitorWaited;
  jlong cbNativeMethodBind;
  jlong cbObjectFree;
  jlong cbResourceExhausted;
  jlong cbSampledObjectAlloc;
  jlong cbSingleStep;
  jlong cbThreadEnd;
  jlong cbThreadStart;
  jlong cbVMDeath;
  jlong cbVMInit;
  jlong cbVMObjectAlloc;

  /* Inspector statistics */
  jlong inspectedMethods;
  jlong inspectedVariables;

  jrawMonitorID debugger_lock;

} ModuleData;

ModuleData *mdata;

// uncomment to enable verbose logginge
// #define DEBUG_ENABLED

// Internal buffer length for all messages
#define MESSAGE_LIMIT 16384

#define FAILURE_EXIT_CODE 74
void
debug(const char* format, ...) {
#ifdef DEBUG_ENABLED
  char dest[MESSAGE_LIMIT];
  va_list argptr;
  va_start(argptr, format);
  vsnprintf(dest, MESSAGE_LIMIT, format, argptr);
  va_end(argptr);
  printf("%s\n", dest);
// fprintf(gdata->log_file, "%s\n", dest);
//  fflush(gdata->log_file);
#endif
}

void
check_jni_exception(JNIEnv *jni, const char *message) {
  jobject exception = jni->ExceptionOccurred();
  if (exception != nullptr) {
    jni->ExceptionDescribe();
    fatal(jni, message);
  }
}

void create_agent_thread(JNIEnv* env, const char *name, jvmtiStartFunction func);
/* JNI helpers with Exception check */
jclass find_class(JNIEnv *env, const char *name);

jfieldID
get_field_id(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
  char message[MESSAGE_LIMIT];
  jfieldID fid = env->GetFieldID(clazz, name, sig);
  snprintf(message, MESSAGE_LIMIT, "Failed to find field %s.", name);
  check_jni_exception(env, message);
  return fid;
}

typedef struct {
  jvmtiEnv *jvmti;
  FILE* log_file;
} GlobalData;

GlobalData * gdata;

jvmtiEnv*
get_jvmti() {
  return gdata->jvmti;
}
void
gdata_init(jvmtiEnv *env) {
  static GlobalData data;
  /* Create initial default values */
  (void) memset(&data, 0, sizeof (GlobalData));
  data.log_file = fopen("JvmtiStressModuleNative.out", "w");
  data.jvmti = env;
  gdata = &data;
}

void
gdata_close() {
  fclose(gdata->log_file);
}

void
set_long_field(JNIEnv *env, jclass cls, jobject obj, const char *fld_name, jlong value) {
  char message[MESSAGE_LIMIT];
  jfieldID fld = get_field_id(env, cls, fld_name, "J");
  env->SetLongField(obj, fld, value);
  snprintf(message, MESSAGE_LIMIT, "Failed to set long field %s.", fld_name);
  check_jni_exception(env, message);
}

jclass
find_class(JNIEnv *env, const char *name) {
  char message[MESSAGE_LIMIT];
  jclass clazz = env->FindClass(name);
  snprintf(message, MESSAGE_LIMIT, "Failed to find class %s.", name);
  check_jni_exception(env, message);
  return clazz;
}

jmethodID
get_method_id(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
  char message[MESSAGE_LIMIT];
  jmethodID method = env->GetMethodID(clazz, name, sig);
  snprintf(message, MESSAGE_LIMIT, "Failed to find method %s.", name);
  check_jni_exception(env, message);
  return method;
}

void
create_agent_thread(JNIEnv *env, const char *name, jvmtiStartFunction func) {
  jclass clazz = nullptr;
  jmethodID thread_ctor = nullptr;
  jthread thread = nullptr;
  jstring name_utf = nullptr;
  jvmtiError err = JVMTI_ERROR_NONE;

  check_jni_exception(env, "JNIException before creating Agent Thread.");
  clazz = find_class(env, "java/lang/Thread");
  thread_ctor = get_method_id(env, clazz, "<init>",
                                    "(Ljava/lang/String;)V");

  name_utf = env->NewStringUTF(name);
  check_jni_exception(env, "Error creating utf name of thread.");

  thread = env->NewObject(clazz, thread_ctor, name_utf);
  check_jni_exception(env, "Error during instantiation of Thread object.");
  err = gdata->jvmti->RunAgentThread(
                     thread, func, NULL, JVMTI_THREAD_NORM_PRIORITY);
  check_jvmti_error(err, "RunAgentThread");
}

static void
trace_stack(jvmtiEnv *jvmti, JNIEnv *jni, jthread thread) {
  jvmtiFrameInfo frames[5];
  jint count = 0;
  jint entry_count = 0;
  int frame_index = 0;
  jvmtiError err = JVMTI_ERROR_NONE;

  debug("In stack_trace: %p", thread);
  err =jvmti->GetStackTrace(thread, 0, 5,
                                frames, &count);
  check_jvmti_error(err, "GetStackTrace");

  debug("Stack depth: %d", count);

  for (frame_index = 0; frame_index < count; frame_index++) {
    int cnt = 0;
    char *method_name = NULL;
    jint method_modifiers = 0;
    jvmtiLocalVariableEntry* table = NULL;
    err =jvmti->GetMethodName(frames[frame_index].method, &method_name, NULL, NULL);
    check_jvmti_error(err, "GetMethodName");

    err =jvmti->GetMethodModifiers(frames[frame_index].method, &method_modifiers);
    check_jvmti_error(err, "GetMethodModifiers");

    debug("Inspecting method: %s, %d", method_name, method_modifiers);
    deallocate(jvmti, jni, method_name);

    err =jvmti->GetLocalVariableTable(frames[frame_index].method, &entry_count, &table);
    if (err == JVMTI_ERROR_NATIVE_METHOD || err == JVMTI_ERROR_ABSENT_INFORMATION
            || err == JVMTI_ERROR_WRONG_PHASE) {
      continue;
    }
    check_jvmti_error(err, "GetLocalVariableTable");

    mdata->inspectedMethods += 1;
    mdata->inspectedVariables += entry_count;

    debug("Variables: ");
    for (cnt = 0; cnt < (int) entry_count; cnt++) {
      debug(" %s  %d", table[cnt].name, (int) table[cnt].slot);
      deallocate(jvmti, jni, table[cnt].name);
      deallocate(jvmti, jni, table[cnt].signature);
      deallocate(jvmti, jni, table[cnt].generic_signature);
    }
    deallocate(jvmti, jni, table);
  }
  debug("---- End of stack inspection %d -----", count);
}

static char*
get_top_method_name(jvmtiEnv *jvmti, jthread thread) {
  jvmtiFrameInfo frames[1];
  jint count;
  char *methodName = NULL;
  jvmtiError err =jvmti->GetStackTrace(thread, 0, 1, frames, &count);
  check_jvmti_error(err, "GetStackTrace");

  err =jvmti->GetMethodName(frames[0].method, &methodName, NULL, NULL);
  check_jvmti_error(err, "GetMethodName");

  return methodName;
}

const char*
bool2str(const jboolean val) {
  return val == JNI_FALSE ? "JNI_FALSE" : "JNI_TRUE";
}

void
raw_monitor_enter(jrawMonitorID m) {
  get_jvmti()->RawMonitorEnter(m);
}

void
raw_monitor_exit(jrawMonitorID m) {
  get_jvmti()->RawMonitorExit(m);
}



static jboolean
should_stop(const volatile jboolean *stop, volatile jboolean *finished) {
  jboolean should_stop = JNI_FALSE;
  raw_monitor_enter(mdata->finished_lock);
  should_stop = *stop;
  debug("check = %s", bool2str(should_stop));
  if (should_stop == JNI_TRUE) {
      *finished = JNI_TRUE;
  }
  raw_monitor_exit(mdata->finished_lock);
  return should_stop;
}

static void JNICALL
inspect_all_threads(jvmtiEnv *jvmti, JNIEnv *jni) {
    jint threads_count = 0;
    jthread *threads = NULL;
    jvmtiError err = JVMTI_ERROR_NONE;
    int t = 0;
    debug("Inspect:  Starting cycle...");
    err =jvmti->GetAllThreads(&threads_count, &threads);
    check_jvmti_error(err, "GetAllThreads");
    for (t = 0; t < (int)threads_count; t++) {
      jvmtiThreadInfo info;
      jthread thread;
      debug("Inspecting thread num %d at addr [%p]",t, threads[t]);
      err = jvmti->GetThreadInfo(threads[t], &info);
      check_jvmti_error(err, "GetThreadInfo");
      // Skip jvmti-related threads to avoid deadlocks
      // The non-intrusive actions are allowed to ensure that results are not affected
      // TODO check if inspection of JFR threads might cause deadlock
      if (strstr(info.name, JVMTI_PREFIX) == NULL && strstr(info.name, "JFR") == NULL) {
        thread = threads[t];
        debug("Inspect: Trying to suspend thread %s", info.name);
        err =jvmti->SuspendThread(thread);
        if (err != JVMTI_ERROR_THREAD_NOT_ALIVE) {
          check_jvmti_error(err, "SuspendThread");
          debug("Inspect:  Suspended thread %s", info.name);
          trace_stack(jvmti, jni, thread);
          debug("Inspect: Trying to resume thread %s", info.name);
          err =jvmti->ResumeThread(thread);
          check_jvmti_error(err, "ResumeThread");
          debug("Inspect:  Resumed thread %s", info.name);
        } else {
          debug("Inspect:  thread %s is not alive. Skipping.", info.name);
        }
      }
      deallocate(jvmti, jni, info.name);
      jni->DeleteLocalRef(info.thread_group);
      jni->DeleteLocalRef(info.context_class_loader);
      jni->DeleteLocalRef(threads[t]);
    }
    deallocate(jvmti, jni, threads);
}

static void JNICALL
agent_debugger(jvmtiEnv *jvmti, JNIEnv *env, void *p) {
  debug("Debugger: Thread started.");
  while (!should_stop(&mdata->agent_request_stop, &mdata->agent)) {
    raw_monitor_enter(mdata->debugger_lock);
    inspect_all_threads(jvmti, env);
    raw_monitor_exit(mdata->debugger_lock);
  }
  debug("Debugger: Thread finished.");
}


/*
 * Events section. Get events info and report summary for each iteration.
 */
static void
register_event(jlong *event) {
  raw_monitor_enter(mdata->events_lock);
  (*event)++;
  debug("event \n");
  raw_monitor_exit(mdata->events_lock);
}

static jlong
get_event_count(jlong *event) {
  jlong result;
  raw_monitor_enter(mdata->events_lock);
  result = *event;
  raw_monitor_exit(mdata->events_lock);
  return result;
}


static void JNICALL
cbVMInit(jvmtiEnv *jvmti, JNIEnv *env, jthread thread) {
  register_event(&mdata->cbVMInit);
  create_agent_thread(env, JVMTI_AGENT_NAME, &agent_debugger);
}

static void JNICALL
cbVMDeath(jvmtiEnv *jvmti, JNIEnv *env) {
  register_event(&mdata->cbVMDeath);
  jboolean finished = JNI_FALSE;
  raw_monitor_enter(mdata->finished_lock);
  mdata->agent_request_stop = JNI_TRUE;
  //set_callbacks(JNI_FALSE);
  raw_monitor_exit(mdata->finished_lock);

  while (!finished) {
    raw_monitor_enter(mdata->finished_lock);
    debug("Shutdown. Completion status: debugger = %s:", bool2str(mdata->agent));
    finished = mdata->agent;
    raw_monitor_exit(mdata->finished_lock);
    sleep_ms(1000);
  }


  debug("Native agent stopped");

}

static void JNICALL
cbThreadStart(jvmtiEnv *jvmti, JNIEnv *env, jthread thread) {
  register_event(&mdata->cbThreadStart);
}

static void JNICALL
cbThreadEnd(jvmtiEnv *jvmti, JNIEnv *env, jthread thread) {
  register_event(&mdata->cbThreadEnd);
}

static void JNICALL
cbClassFileLoadHook(jvmtiEnv *jvmti, JNIEnv* env,
                    jclass class_being_redefined, jobject loader,
                    const char* name, jobject protection_domain,
                    jint class_data_len, const unsigned char *class_data,
                    jint *new_class_data_len, unsigned char **new_class_data) {
  register_event(&mdata->cbClassFileLoadHook);
}

static void JNICALL
cbClassLoad(jvmtiEnv *jvmti, JNIEnv *env, jthread thread, jclass klass) {
  register_event(&mdata->cbClassLoad);
}

static void JNICALL
cbClassPrepare(jvmtiEnv *jvmti, JNIEnv *env, jthread thread, jclass klass) {
  register_event(&mdata->cbClassPrepare);
}

static void JNICALL
cbDataDumpRequest(jvmtiEnv *jvmti) {
  register_event(&mdata->cbDataDumpRequest);
}

static void JNICALL
cbException(jvmtiEnv *jvmti,
            JNIEnv *jni,
            jthread thread,
            jmethodID method,
            jlocation location,
            jobject exception,
            jmethodID catch_method,
            jlocation catch_location) {
  register_event(&mdata->cbException);
}

static void JNICALL
cbExceptionCatch(jvmtiEnv *jvmti, JNIEnv *env,
                 jthread thread, jmethodID method, jlocation location,
                 jobject exception) {
  register_event(&mdata->cbExceptionCatch);
}

static void JNICALL
cbMonitorWait(jvmtiEnv *jvmti, JNIEnv *env,
              jthread thread, jobject object, jlong timeout) {
  register_event(&mdata->cbMonitorWait);
}

static void JNICALL
cbMonitorWaited(jvmtiEnv *jvmti, JNIEnv *env,
                jthread thread, jobject object, jboolean timed_out) {
  register_event(&mdata->cbMonitorWaited);
}

static void JNICALL
cbMonitorContendedEnter(jvmtiEnv *jvmti, JNIEnv *env,
                        jthread thread, jobject object) {
  register_event(&mdata->cbMonitorContendedEnter);
}

static void JNICALL
cbMonitorContendedEntered(jvmtiEnv *jvmti, JNIEnv* env,
                          jthread thread, jobject object) {
  register_event(&mdata->cbMonitorContendedEntered);
}

static void JNICALL
cbGarbageCollectionStart(jvmtiEnv *jvmti) {
  register_event(&mdata->cbGarbageCollectionStart);
}

static void JNICALL
cbGarbageCollectionFinish(jvmtiEnv *jvmti) {
  register_event(&mdata->cbGarbageCollectionFinish);
}

static void JNICALL
cbObjectFree(jvmtiEnv *jvmti, jlong tag) {
  register_event(&mdata->cbObjectFree);
}

static void JNICALL
cbBreakpoint(jvmtiEnv *jvmti,
             JNIEnv *jni,
             jthread thread,
             jmethodID method,
             jlocation location) {
  static long breakpoint_cnt = 0;
  register_event(&mdata->cbBreakpoint);
}

static void JNICALL
cbSingleStep(jvmtiEnv *jvmti,
             JNIEnv *jni,
             jthread thread,
             jmethodID method,
             jlocation location) {
  register_event(&mdata->cbSingleStep);
}

static void JNICALL
cbFieldAccess(jvmtiEnv *jvmti,
              JNIEnv *jni,
              jthread thread,
              jmethodID method,
              jlocation location,
              jclass field_klass,
              jobject object,
              jfieldID field) {
  register_event(&mdata->cbFieldAccess);
}

static void JNICALL
cbFieldModification(jvmtiEnv *jvmti,
                    JNIEnv *jni,
                    jthread thread,
                    jmethodID method,
                    jlocation location,
                    jclass field_klass,
                    jobject object,
                    jfieldID field,
                    char signature_type,
                    jvalue new_value) {
  register_event(&mdata->cbFieldModification);
}

static void JNICALL
cbFramePop(jvmtiEnv *jvmti,
           JNIEnv *jni,
           jthread thread,
           jmethodID method,
           jboolean was_popped_by_exception) {
  register_event(&mdata->cbFramePop);
}

static void JNICALL
cbMethodEntry(jvmtiEnv *jvmti,
              JNIEnv *jni,
              jthread thread,
              jmethodID method) {
  register_event(&mdata->cbMethodEntry);
}

static void JNICALL
cbMethodExit(jvmtiEnv *jvmti,
             JNIEnv *jni,
             jthread thread,
             jmethodID method,
             jboolean was_popped_by_exception,
             jvalue return_value) {
  register_event(&mdata->cbMethodExit);
}

static void JNICALL
cbNativeMethodBind(jvmtiEnv *jvmti,
                   JNIEnv *jni,
                   jthread thread,
                   jmethodID method,
                   void* address,
                   void** new_address_ptr) {
  register_event(&mdata->cbNativeMethodBind);
}

static void JNICALL
cbCompiledMethodLoad(jvmtiEnv *jvmti,
                     jmethodID method,
                     jint code_size,
                     const void* code_addr,
                     jint map_length,
                     const jvmtiAddrLocationMap* map,
                     const void* compile_info) {
  register_event(&mdata->cbCompiledMethodLoad);
}

static void JNICALL
cbCompiledMethodUnload(jvmtiEnv *jvmti,
                       jmethodID method,
                       const void* code_addr) {
  register_event(&mdata->cbCompiledMethodUnload);
}

static void JNICALL
cbDynamicCodeGenerated(jvmtiEnv *jvmti,
                       const char* name,
                       const void* address,
                       jint length) {
  register_event(&mdata->cbDynamicCodeGenerated);
}

static void JNICALL
cbResourceExhausted(jvmtiEnv *jvmti,
                    JNIEnv *jni,
                    jint flags,
                    const void* reserved,
                    const char* description) {
  register_event(&mdata->cbResourceExhausted);
}

static void JNICALL
cbVMObjectAlloc(jvmtiEnv *jvmti,
                JNIEnv *jni,
                jthread thread,
                jobject object,
                jclass object_klass,
                jlong size) {
  register_event(&mdata->cbVMObjectAlloc);
}

static void JNICALL
cbSampledObjectAlloc(jvmtiEnv *jvmti,
                     JNIEnv *jni,
                     jthread thread,
                     jobject object,
                     jclass object_klass,
                     jlong size) {
  register_event(&mdata->cbSampledObjectAlloc);
}

int
is_event_frequent(int event) {
  return event == JVMTI_EVENT_SINGLE_STEP
      || event == JVMTI_EVENT_METHOD_ENTRY
      || event == JVMTI_EVENT_METHOD_EXIT
      || event == JVMTI_EVENT_EXCEPTION_CATCH
      || event == JVMTI_EVENT_EXCEPTION;
}

int
is_event_excluded(int event) {
  int i = 0;
  while(i < mdata->events_excluded_size) {
    if (event == mdata->events_excluded[i]) {
      return JNI_TRUE;
    }
    i++;
  }
  return JNI_FALSE;
}

/*
 * This helper method is used by enable_frequent_events() and enable_common_events().
 * It enables frequent OR non-frequent events.
 */
static void
enable_events(jboolean update_frequent_events) {
  debug("Enabling events\n");
  jvmtiError err = JVMTI_ERROR_NONE;
  for(int event = JVMTI_MIN_EVENT_TYPE_VAL; event < JVMTI_MAX_EVENT_TYPE_VAL; event++) {
    if (is_event_excluded(event)) {
      debug("Event %d excluded.", event);
      continue;
    }
    if (is_event_frequent(event) != update_frequent_events ) {
      debug("Evecnt %d is not enabled as frequent/slow.", event);
      continue;
    }
    err = get_jvmti()->SetEventNotificationMode(JVMTI_ENABLE, static_cast<jvmtiEvent>(event), NULL);
    check_jvmti_error(err, "SetEventNotificationMode");
  }
  debug("Enabling events done\n");
}

static void
enable_frequent_events() {
  enable_events(JNI_TRUE);
}

static void
enable_common_events() {
  enable_events(JNI_FALSE);
}


static void
disable_all_events() {
  jvmtiError err = JVMTI_ERROR_NONE;
  int event = JVMTI_MIN_EVENT_TYPE_VAL - 1;
  while(event++ < JVMTI_MAX_EVENT_TYPE_VAL) {
    err = get_jvmti()->SetEventNotificationMode(JVMTI_DISABLE, static_cast<jvmtiEvent>(event), NULL);
    check_jvmti_error(err, "SetEventNotificationMode");
  }
}

static void
set_callbacks(jboolean on) {
  jvmtiError err = JVMTI_ERROR_NONE;
  jvmtiEventCallbacks callbacks;

  (void) memset(&callbacks, 0, sizeof (callbacks));
  if (on == JNI_FALSE) {
    err = get_jvmti()->SetEventCallbacks(&callbacks, (int) sizeof (jvmtiEventCallbacks));
    check_jvmti_error(err, "SetEventCallbacks");
    return;
  }
  callbacks.Breakpoint = &cbBreakpoint;
  callbacks.ClassFileLoadHook = &cbClassFileLoadHook;
  callbacks.ClassLoad = &cbClassLoad;
  callbacks.ClassPrepare = &cbClassPrepare;
  callbacks.CompiledMethodLoad = &cbCompiledMethodLoad;
  callbacks.CompiledMethodUnload = &cbCompiledMethodUnload;
  callbacks.DataDumpRequest = &cbDataDumpRequest;
  callbacks.DynamicCodeGenerated = &cbDynamicCodeGenerated;
  callbacks.Exception = &cbException;
  callbacks.ExceptionCatch = &cbExceptionCatch;
  callbacks.FieldAccess = &cbFieldAccess;
  callbacks.FieldModification = &cbFieldModification;
  callbacks.FramePop = &cbFramePop;
  callbacks.GarbageCollectionFinish = &cbGarbageCollectionFinish;
  callbacks.GarbageCollectionStart = &cbGarbageCollectionStart;
  callbacks.MethodEntry = &cbMethodEntry;
  callbacks.MethodExit = &cbMethodExit;
  callbacks.MonitorContendedEnter = &cbMonitorContendedEnter;
  callbacks.MonitorContendedEntered = &cbMonitorContendedEntered;
  callbacks.MonitorWait = &cbMonitorWait;
  callbacks.MonitorWaited = &cbMonitorWaited;
  callbacks.NativeMethodBind = &cbNativeMethodBind;
  callbacks.ObjectFree = &cbObjectFree;
  callbacks.ResourceExhausted = &cbResourceExhausted;
  callbacks.SampledObjectAlloc = &cbSampledObjectAlloc;
  callbacks.SingleStep = &cbSingleStep;
  callbacks.ThreadEnd = &cbThreadEnd;
  callbacks.ThreadStart = &cbThreadStart;
  callbacks.VMDeath = &cbVMDeath;
  callbacks.VMInit = &cbVMInit;
  callbacks.VMObjectAlloc = &cbVMObjectAlloc;
  err = get_jvmti()->SetEventCallbacks(&callbacks, (int) sizeof (jvmtiEventCallbacks));
  check_jvmti_error(err, "SetEventCallbacks");
}


static jint JNICALL
heap_iteration_callback(jlong class_tag, jlong size, jlong* tag_ptr, jint length, void* user_data) {
  int* count = (int*) user_data;
  *count += 1;
  return JVMTI_VISIT_OBJECTS;
}

static jint
get_heap_info(JNIEnv *env, jclass klass) {
  jvmtiError err = JVMTI_ERROR_NONE;
  int count = 0;
  jvmtiHeapCallbacks callbacks;
  (void) memset(&callbacks, 0, sizeof (callbacks));
  callbacks.heap_iteration_callback = &heap_iteration_callback;
  err = get_jvmti()->IterateThroughHeap(0, klass, &callbacks, &count);
  check_jvmti_error(err, "IterateThroughHeap");
  return count;
}

/*
 * This method starts all the work. Should be called in JvmtiStressModule#init() after java-based properties are initialized..
 * Also it set the JVMTI callback functions and setup event modes.
 */
JNIEXPORT jboolean JNICALL
Java_JvmtiStressAgent_initNative(JNIEnv *env,
                  jobject _this,
                  jobject settings) {

  set_callbacks(JNI_TRUE);
  if (mdata->are_events_enabled) {
    enable_common_events();
  }

  debug("Native agent initialization completed");
  return JNI_TRUE;
}

/*
 * This method finishes all native work. Should be called in JvmtiStressModule#onShutdown().
 * Method waits until jvmti threads stop so they don't generate errors after shutdown.
 */
JNIEXPORT jboolean JNICALL
Java_JvmtiStressAgent_shutdownNative(JNIEnv *env, jobject _this) {
  jboolean finished = JNI_FALSE;
  raw_monitor_enter(mdata->finished_lock);
  mdata->agent_request_stop = JNI_TRUE;
  set_callbacks(JNI_FALSE);
  raw_monitor_exit(mdata->finished_lock);

  while (!finished) {
    raw_monitor_enter(mdata->finished_lock);
    debug("Shutdown. Completion status: debugger = %s:", bool2str(mdata->agent));
    finished = mdata->agent;
    raw_monitor_exit(mdata->finished_lock);
    sleep_ms(1000);
  }


  debug("Native agent stopped");
  return JNI_TRUE;
}

/*
 * This method is invoked at the beginning of each test iteration.
 * It is used to reset all iteration specific data.
 */
JNIEXPORT void JNICALL
Java_startIteration(JNIEnv *env, jobject _this) {
  jvmtiError err = JVMTI_ERROR_NONE;
  if (mdata->are_events_enabled) {
    disable_all_events();
    raw_monitor_enter(mdata->events_lock);
    mdata->cbBreakpoint = 0;
    mdata->cbClassFileLoadHook = 0;
    mdata->cbClassLoad = 0;
    mdata->cbClassPrepare = 0;
    mdata->cbCompiledMethodLoad = 0;
    mdata->cbCompiledMethodUnload = 0;
    mdata->cbDataDumpRequest = 0;
    mdata->cbDynamicCodeGenerated = 0;
    mdata->cbException = 0;
    mdata->cbExceptionCatch = 0;
    mdata->cbFieldAccess = 0;
    mdata->cbFieldModification = 0;
    mdata->cbFramePop = 0;
    mdata->cbGarbageCollectionFinish = 0;
    mdata->cbGarbageCollectionStart = 0;
    mdata->cbMethodEntry = 0;
    mdata->cbMethodExit = 0;
    mdata->cbMonitorContendedEnter = 0;
    mdata->cbMonitorContendedEntered = 0;
    mdata->cbMonitorWait = 0;
    mdata->cbMonitorWaited = 0;
    mdata->cbNativeMethodBind = 0;
    mdata->cbObjectFree = 0;
    mdata->cbResourceExhausted = 0;
    mdata->cbSampledObjectAlloc = 0;
    mdata->cbSingleStep = 0;
    mdata->cbThreadEnd = 0;
    mdata->cbThreadStart = 0;
    mdata->cbVMDeath = 0;
    mdata->cbVMInit = 0;
    mdata->cbVMObjectAlloc = 0;
    raw_monitor_exit(mdata->events_lock);
    enable_common_events();
  }
  raw_monitor_enter(mdata->debugger_lock);
  mdata->inspectedMethods = 0;
  mdata->inspectedVariables = 0;
  raw_monitor_exit(mdata->debugger_lock);

  err = get_jvmti()->SetHeapSamplingInterval(mdata->heap_sampling_interval);
  check_jvmti_error(err, "SetHeapSamplingInterval");

  if (mdata->is_debugger_enabled)  {
    mdata->agent = JNI_FALSE;
    mdata->agent_request_stop = JNI_FALSE;
    create_agent_thread(env, JVMTI_AGENT_NAME, &agent_debugger);
  }

}

/*
 * This method is invoked at the end of each test iteration.
 * It is used to collect test statistics per iteration for later analysis.
 */
JNIEXPORT jobject JNICALL
Java_finishIteration(JNIEnv *env, jobject _this) {
  jvmtiError err = JVMTI_ERROR_NONE;
  jclass cls;
  jmethodID constructor;
  jobject obj;
  jclass kls;
  jint obj_count;

  if (mdata->is_debugger_enabled)  {
    raw_monitor_enter(mdata->finished_lock);
    mdata->agent_request_stop = JNI_TRUE;
    raw_monitor_exit(mdata->finished_lock);
  }

  cls = find_class(env, JVMTI_STATISTICS);
  constructor = find_method(get_jvmti(), env, cls, "<init>"/*, "()V"*/);
  obj = env->NewObject(cls, constructor);
  if (mdata->are_events_enabled) {
    if (mdata->frequent_events_interval != 0) {
      enable_frequent_events();
      // Enabled very frequent performance sensitive events for very limited time only
      sleep_ms(mdata->frequent_events_interval);
    }
    disable_all_events();
    enable_common_events();
  }


  // Iterate through heap and get some statistics
  kls = find_class(env, "java/lang/String");
  obj_count = get_heap_info(env, kls);
  obj_count = get_heap_info(env, NULL);

  err = get_jvmti()->SetHeapSamplingInterval(0);
  check_jvmti_error(err, "SetHeapSamplingInterval");
  return obj;
}

static
void get_capabilities(void) {
  jvmtiError err = JVMTI_ERROR_NONE;
  jvmtiCapabilities capabilities;
  (void) memset(&capabilities, 0, sizeof (capabilities));
  err = get_jvmti()->GetPotentialCapabilities(&capabilities);
  check_jvmti_error(err, "GetPotentialCapabilities");
  err = get_jvmti()->AddCapabilities(&capabilities);
  check_jvmti_error(err, "AddCapabilities");
}

static ModuleData*
mdata_init() {
  static ModuleData data;
  (void) memset(&data, 0, sizeof (ModuleData));

  data.agent_request_stop = JNI_FALSE;

  /* Set jvmti stress properties */
  data.debugger_interval = 1000;
  data.heap_sampling_interval = 1000;
  data.frequent_events_interval = 100;
  data.debugger_watch_methods = 100;
  data.is_debugger_enabled = true;
  data.are_events_enabled = true;

  /* Set array of excluded events if needed */
  //data,events_excluded_size = 0;
  // data.events_excluded = static_cast<int *>(malloc(sizeof(jint) * mdata->events_excluded_size));
  // data.events_excluded[0] = 74;


  return &data;
}

void
mdata_close(void) {
  free(mdata->events_excluded);
}

JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
  jvmtiEnv *jvmti = NULL;
  jint res = vm->GetEnv((void **) &jvmti, JVMTI_VERSION_21);
  if (res != JNI_OK) {
    return JNI_ERR;
  }

  mdata = mdata_init();

  gdata_init(jvmti);
  get_capabilities();

  mdata->finished_lock = create_raw_monitor(jvmti, "Finished lock");
  mdata->events_lock = create_raw_monitor(jvmti, "Events lock");
  mdata->debugger_lock = create_raw_monitor(jvmti, "Debugger lock");
  set_callbacks(JNI_TRUE);
  enable_common_events();

  return JNI_OK;
}

JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM *vm) {
//   destroy_raw_monitor(get_jvmti(), mdata->finished_lock);
  //destroy_raw_monitor(mdata->events_lock);
  //destroy_raw_monitor(mdata->debugger_lock);
  //gdata_close();
}
