package com.google.android.gms.internal.ads;

import android.util.Log;
import java.util.Locale;

/* loaded from: classes2.dex */
public abstract class H3 {
    public static final boolean a = Log.isLoggable("Volley", 2);
    public static final String b = H3.class.getName();

    public static void a(String str, Object... objArr) {
        Log.e("Volley", c(str, objArr));
    }

    public static void b(String str, Object... objArr) {
        if (a) {
            c(str, objArr);
        }
    }

    public static String c(String str, Object... objArr) {
        String strL;
        String str2 = String.format(Locale.US, str, objArr);
        StackTraceElement[] stackTrace = new Throwable().fillInStackTrace().getStackTrace();
        int i = 2;
        while (true) {
            if (i >= stackTrace.length) {
                strL = "<unknown>";
                break;
            }
            if (!stackTrace[i].getClassName().equals(b)) {
                String className = stackTrace[i].getClassName();
                String strSubstring = className.substring(className.lastIndexOf(46) + 1);
                strL = android.support.v4.media.session.a.l(strSubstring.substring(strSubstring.lastIndexOf(36) + 1), ".", stackTrace[i].getMethodName());
                break;
            }
            i++;
        }
        Locale locale = Locale.US;
        long id = Thread.currentThread().getId();
        StringBuilder sb = new StringBuilder("[");
        sb.append(id);
        sb.append("] ");
        sb.append(strL);
        return android.support.v4.media.session.a.t(sb, ": ", str2);
    }
}
