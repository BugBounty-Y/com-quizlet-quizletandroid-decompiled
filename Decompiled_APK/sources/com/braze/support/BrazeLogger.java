package com.braze.support;

import android.util.Log;
import com.braze.AbstractC1484j;
import com.braze.storage.D;
import com.braze.storage.F;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes.dex */
public final class BrazeLogger {
    private static boolean hasLogLevelBeenSetForAppRun;
    private static boolean isSystemPropLogLevelSet;
    private static kotlin.jvm.functions.c onLoggedCallback;
    private static kotlin.jvm.functions.d sdkDebuggerCallback;
    public static final BrazeLogger INSTANCE = new BrazeLogger();
    private static int logLevel = 4;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class Priority {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ Priority[] $VALUES;
        private final int logLevel;
        public static final Priority D = new Priority("D", 0, 3);
        public static final Priority I = new Priority("I", 1, 4);
        public static final Priority E = new Priority("E", 2, 6);
        public static final Priority V = new Priority("V", 3, 2);
        public static final Priority W = new Priority("W", 4, 5);

        private static final /* synthetic */ Priority[] $values() {
            return new Priority[]{D, I, E, V, W};
        }

        static {
            Priority[] priorityArr$values = $values();
            $VALUES = priorityArr$values;
            $ENTRIES = AbstractC3328d.f(priorityArr$values);
        }

        private Priority(String str, int i, int i2) {
            this.logLevel = i2;
        }

        public static Priority valueOf(String str) {
            return (Priority) Enum.valueOf(Priority.class, str);
        }

        public static Priority[] values() {
            return (Priority[]) $VALUES.clone();
        }

        public final int getLogLevel() {
            return this.logLevel;
        }
    }

    private BrazeLogger() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_logLevel_$lambda$0(int i) {
        return android.support.v4.media.session.a.f(i, "Log level already set via system property. BrazeLogger.setLogLevel() ignored for level: ");
    }

    public static /* synthetic */ void brazelog$default(BrazeLogger brazeLogger, Object obj, Priority priority, Throwable th, boolean z, Function0 function0, int i, Object obj2) {
        if ((i & 1) != 0) {
            priority = Priority.D;
        }
        Priority priority2 = priority;
        if ((i & 2) != 0) {
            th = null;
        }
        Throwable th2 = th;
        if ((i & 4) != 0) {
            z = false;
        }
        brazeLogger.brazelog(obj, priority2, th2, z, (Function0<String>) function0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String brazelog$lambda$7(Function0 function0) {
        return INSTANCE.toStringSafe(function0);
    }

    public static final void checkForSystemLogLevelProperty(boolean z) {
        String strA = s.a("log.tag.BRAZE");
        if ("verbose".equalsIgnoreCase(StringsKt.g0(s.a("log.tag.APPBOY")).toString()) || "verbose".equalsIgnoreCase(StringsKt.g0(strA).toString())) {
            setLogLevel(2);
            isSystemPropLogLevelSet = true;
            BrazeLogger brazeLogger = INSTANCE;
            brazelog$default(brazeLogger, (Object) brazeLogger, Priority.I, (Throwable) null, false, (Function0) new F(14), 6, (Object) null);
        }
    }

    public static /* synthetic */ void checkForSystemLogLevelProperty$default(boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = true;
        }
        checkForSystemLogLevelProperty(z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String checkForSystemLogLevelProperty$lambda$1() {
        return "BrazeLogger log level set to VERBOSE via device system property for BRAZE/APPBOY. Note that subsequent calls to BrazeLogger.setLogLevel() will have no effect.";
    }

    public static /* synthetic */ void d$default(String str, String str2, Throwable th, int i, Object obj) {
        if ((i & 4) != 0) {
            th = null;
        }
        d(str, str2, th);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String d$lambda$3(String str) {
        return str;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String e$lambda$6(String str) {
        return str;
    }

    public static final String getBrazeLogTag(Class<?> classForTag) {
        Intrinsics.checkNotNullParameter(classForTag, "classForTag");
        String name = classForTag.getName();
        int length = name.length();
        if (length > 65) {
            name = name.substring(length - 65);
            Intrinsics.checkNotNullExpressionValue(name, "substring(...)");
        }
        return AbstractC1484j.a("Braze v36.0.0 .", name);
    }

    public static final void i(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        i$default(tag, msg, null, 4, null);
    }

    public static /* synthetic */ void i$default(String str, String str2, Throwable th, int i, Object obj) {
        if ((i & 4) != 0) {
            th = null;
        }
        i(str, str2, th);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String i$lambda$4(String str) {
        return str;
    }

    public static final void setInitialLogLevelFromConfiguration(int i) {
        if (hasLogLevelBeenSetForAppRun) {
            return;
        }
        setLogLevel(i);
    }

    public static final void setLogLevel(int i) {
        if (isSystemPropLogLevelSet) {
            BrazeLogger brazeLogger = INSTANCE;
            brazelog$default(brazeLogger, (Object) brazeLogger, Priority.W, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 10), 6, (Object) null);
        } else {
            hasLogLevelBeenSetForAppRun = true;
            logLevel = i;
        }
    }

    private final String toStringSafe(Function0<? extends Object> function0) {
        try {
            return String.valueOf(function0.invoke());
        } catch (Exception unused) {
            return "";
        }
    }

    public static final void v(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        v$default(tag, msg, null, 4, null);
    }

    public static /* synthetic */ void v$default(String str, String str2, Throwable th, int i, Object obj) {
        if ((i & 4) != 0) {
            th = null;
        }
        v(str, str2, th);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String v$lambda$2(String str) {
        return str;
    }

    public static final void w(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        w$default(tag, msg, null, 4, null);
    }

    public static /* synthetic */ void w$default(String str, String str2, Throwable th, int i, Object obj) {
        if ((i & 4) != 0) {
            th = null;
        }
        w(str, str2, th);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String w$lambda$5(String str) {
        return str;
    }

    public final String brazeLogTag(Object obj) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        String name = obj.getClass().getName();
        String strD0 = StringsKt.d0(name, '$');
        String strC0 = StringsKt.c0(strD0, strD0, '.');
        return strC0.length() == 0 ? getBrazeLogTag(name) : getBrazeLogTag(strC0);
    }

    public final void brazelog(Object obj, Priority priority, Throwable th, boolean z, Function0<String> message) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(message, "message");
        if (logLevel <= priority.getLogLevel() || sdkDebuggerCallback != null) {
            brazelog(brazeLogTag(obj), priority, th, z, message);
        }
    }

    public final void setSdkDebuggerCallback$android_sdk_base_release(kotlin.jvm.functions.d dVar) {
        sdkDebuggerCallback = dVar;
    }

    public static final void d(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        d$default(tag, msg, null, 4, null);
    }

    public static final void e(String tag, String msg, Throwable tr) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(tr, "tr");
        brazelog$default(INSTANCE, tag, Priority.D, tr, false, (Function0) new D(msg, 24), 8, (Object) null);
    }

    public static final void i(String tag, String msg, Throwable th) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        brazelog$default(INSTANCE, tag, Priority.I, th, false, (Function0) new D(msg, 23), 8, (Object) null);
    }

    public static final void v(String tag, String msg, Throwable th) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        brazelog$default(INSTANCE, tag, Priority.V, th, false, (Function0) new D(msg, 21), 8, (Object) null);
    }

    public static final void w(String tag, String msg, Throwable th) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        brazelog$default(INSTANCE, tag, Priority.W, th, false, (Function0) new D(msg, 22), 8, (Object) null);
    }

    public static /* synthetic */ void brazelog$default(BrazeLogger brazeLogger, String str, Priority priority, Throwable th, boolean z, Function0 function0, int i, Object obj) {
        if ((i & 2) != 0) {
            priority = Priority.D;
        }
        Priority priority2 = priority;
        if ((i & 4) != 0) {
            th = null;
        }
        Throwable th2 = th;
        if ((i & 8) != 0) {
            z = false;
        }
        brazeLogger.brazelog(str, priority2, th2, z, (Function0<String>) function0);
    }

    public static final void d(String tag, String msg, Throwable th) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        brazelog$default(INSTANCE, tag, Priority.D, th, false, (Function0) new D(msg, 20), 8, (Object) null);
    }

    public final void brazelog(String tag, Priority priority, Throwable th, boolean z, Function0<String> message) {
        kotlin.jvm.functions.d dVar;
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(message, "message");
        kotlin.u uVarB = kotlin.l.b(new u(0, message));
        kotlin.jvm.functions.c cVar = onLoggedCallback;
        if (cVar != null) {
            cVar.invoke(priority, uVarB.getValue(), th);
        }
        if (!z && (dVar = sdkDebuggerCallback) != null) {
            dVar.invoke(tag, priority, uVarB.getValue(), th);
        }
        if (logLevel <= priority.getLogLevel()) {
            int i = b.a[priority.ordinal()];
            if (i == 1) {
                if (th == null) {
                    return;
                } else {
                    return;
                }
            }
            if (i == 2) {
                if (th == null) {
                    Log.i(tag, (String) uVarB.getValue());
                    return;
                } else {
                    Log.i(tag, (String) uVarB.getValue(), th);
                    return;
                }
            }
            if (i == 3) {
                if (th == null) {
                    Log.w(tag, (String) uVarB.getValue());
                    return;
                } else {
                    Log.e(tag, (String) uVarB.getValue(), th);
                    return;
                }
            }
            if (i == 4) {
                if (th == null) {
                    Log.w(tag, (String) uVarB.getValue());
                    return;
                } else {
                    Log.w(tag, (String) uVarB.getValue(), th);
                    return;
                }
            }
            if (i != 5) {
                throw new NoWhenBranchMatchedException();
            }
            if (th == null) {
            }
        }
    }

    public final String getBrazeLogTag(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return "Braze v36.0.0 ." + str;
    }
}
