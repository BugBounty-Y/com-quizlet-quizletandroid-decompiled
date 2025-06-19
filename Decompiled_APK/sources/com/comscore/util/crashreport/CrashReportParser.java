package com.comscore.util.crashreport;

/* loaded from: classes.dex */
public interface CrashReportParser {
    String reportToString(CrashReport crashReport);

    CrashReport stringToReport(String str);
}
