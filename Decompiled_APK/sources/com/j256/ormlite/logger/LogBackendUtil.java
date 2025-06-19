package com.j256.ormlite.logger;

import java.io.PrintWriter;
import java.io.StringWriter;

/* loaded from: classes2.dex */
public class LogBackendUtil {
    public static String throwableToString(Throwable th) {
        StringWriter stringWriter = new StringWriter();
        th.printStackTrace(new PrintWriter(stringWriter));
        return stringWriter.toString();
    }
}
