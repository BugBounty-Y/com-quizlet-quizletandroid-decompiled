package com.snowplowanalytics.core.tracker;

import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Thread.UncaughtExceptionHandler {
    public final Thread.UncaughtExceptionHandler a = Thread.getDefaultUncaughtExceptionHandler();

    public static String a(int i, String str) {
        if (str == null) {
            return null;
        }
        int length = str.length();
        if (length <= i) {
            i = length;
        }
        String strSubstring = str.substring(0, i);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread t, Throwable e) {
        String strA;
        Intrinsics.checkNotNullParameter(t, "t");
        Intrinsics.checkNotNullParameter(e, "e");
        Intrinsics.checkNotNullExpressionValue("c", "TAG");
        e.a("c", "Uncaught exception being tracked...", new Object[0]);
        String strA2 = a(2048, e.getMessage());
        if (strA2 == null || strA2.length() == 0) {
            strA2 = "Android Exception. Null or empty message found";
        }
        Intrinsics.checkNotNullParameter(e, "e");
        StringWriter stringWriter = new StringWriter();
        e.printStackTrace(new PrintWriter(stringWriter));
        String string = stringWriter.toString();
        Intrinsics.checkNotNullExpressionValue(string, "sw.toString()");
        String strA3 = a(8096, string);
        String strA4 = a(1024, t.getName());
        StackTraceElement[] stackTrace = e.getStackTrace();
        Intrinsics.checkNotNullExpressionValue(stackTrace, "e.stackTrace");
        if (stackTrace.length == 0) {
            strA = null;
        } else {
            StackTraceElement stackTraceElement = e.getStackTrace()[0];
            int lineNumber = stackTraceElement.getLineNumber();
            numValueOf = lineNumber >= 0 ? Integer.valueOf(lineNumber) : null;
            strA = a(1024, stackTraceElement.getClassName());
        }
        String strA5 = a(1024, e.getClass().getName());
        HashMap map = new HashMap();
        E6.a("message", strA2, map);
        E6.a("stackTrace", strA3, map);
        E6.a("threadName", strA4, map);
        E6.a("threadId", Long.valueOf(t.getId()), map);
        E6.a("programmingLanguage", "JAVA", map);
        E6.a("lineNumber", numValueOf, map);
        E6.a("className", strA, map);
        E6.a("exceptionName", strA5, map);
        E6.a("isFatal", Boolean.TRUE, map);
        com.snowplowanalytics.snowplow.event.f fVar = new com.snowplowanalytics.snowplow.event.f(new com.snowplowanalytics.snowplow.payload.a("iglu:com.snowplowanalytics.snowplow/application_error/jsonschema/1-0-0", map));
        HashMap map2 = new HashMap();
        map2.put("event", fVar);
        com.snowplowanalytics.core.utils.c.b(map2, "SnowplowCrashReporting");
        Thread.UncaughtExceptionHandler uncaughtExceptionHandler = this.a;
        if (uncaughtExceptionHandler != null) {
            uncaughtExceptionHandler.uncaughtException(t, e);
        }
    }
}
