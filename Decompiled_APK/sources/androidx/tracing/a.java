package androidx.tracing;

import android.os.Trace;

/* loaded from: classes.dex */
public abstract class a {
    public static void a(String str, int i) {
        Trace.beginAsyncSection(str, i);
    }

    public static void b(String str, int i) {
        Trace.endAsyncSection(str, i);
    }

    public static boolean c() {
        return Trace.isEnabled();
    }

    public static void d(int i, String str) {
        Trace.setCounter(str, i);
    }
}
