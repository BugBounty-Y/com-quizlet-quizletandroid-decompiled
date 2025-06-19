package com.android.volley;

import android.util.Log;
import java.util.Locale;

/* loaded from: classes.dex */
public abstract class y {
    public static final boolean a = Log.isLoggable("Volley", 2);
    public static final String b = y.class.getName();

    public static String a(String str, Object... objArr) {
        String string;
        String str2 = String.format(Locale.US, str, objArr);
        StackTraceElement[] stackTrace = new Throwable().fillInStackTrace().getStackTrace();
        int i = 2;
        while (true) {
            if (i >= stackTrace.length) {
                string = "<unknown>";
                break;
            }
            if (!stackTrace[i].getClassName().equals(b)) {
                String className = stackTrace[i].getClassName();
                String strSubstring = className.substring(className.lastIndexOf(46) + 1);
                StringBuilder sbX = android.support.v4.media.session.a.x(strSubstring.substring(strSubstring.lastIndexOf(36) + 1), ".");
                sbX.append(stackTrace[i].getMethodName());
                string = sbX.toString();
                break;
            }
            i++;
        }
        Locale locale = Locale.US;
        long id = Thread.currentThread().getId();
        StringBuilder sb = new StringBuilder("[");
        sb.append(id);
        sb.append("] ");
        sb.append(string);
        return android.support.v4.media.session.a.t(sb, ": ", str2);
    }

    public static void b(String str, Object... objArr) {
        Log.e("Volley", a(str, objArr));
    }

    public static void c(String str, Object... objArr) {
        if (a) {
            a(str, objArr);
        }
    }
}
