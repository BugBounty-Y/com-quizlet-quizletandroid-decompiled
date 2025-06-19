package com.snowplowanalytics.snowplow.event;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends a {
    public final String b;
    public final String c;
    public final Throwable d;

    public g(String source, String message, Throwable th) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(message, "message");
        this.b = source;
        this.c = message;
        this.d = th;
    }

    public static String c(int i, String str) {
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

    @Override // com.snowplowanalytics.snowplow.event.a
    public final Map a() {
        String strC = c(2048, this.c);
        if (strC == null || strC.length() == 0) {
            strC = "Empty message found";
        }
        HashMap map = new HashMap();
        map.put("className", this.b);
        map.put("message", strC);
        Throwable e = this.d;
        if (e != null) {
            Intrinsics.checkNotNullParameter(e, "e");
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            String string = stringWriter.toString();
            Intrinsics.checkNotNullExpressionValue(string, "sw.toString()");
            String strC2 = c(8192, string);
            String strC3 = c(1024, e.getClass().getName());
            map.put("stackTrace", strC2);
            map.put("exceptionName", strC3);
        }
        return map;
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final String b() {
        return "iglu:com.snowplowanalytics.snowplow/diagnostic_error/jsonschema/1-0-0";
    }
}
