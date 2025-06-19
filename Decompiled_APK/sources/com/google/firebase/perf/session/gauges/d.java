package com.google.firebase.perf.session.gauges;

import android.app.ActivityManager;
import android.content.Context;

/* loaded from: classes2.dex */
public final class d {
    public final Runtime a = Runtime.getRuntime();
    public final ActivityManager b;
    public final ActivityManager.MemoryInfo c;

    static {
        com.google.firebase.perf.logging.a.d();
    }

    public d(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        this.b = activityManager;
        ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
        this.c = memoryInfo;
        activityManager.getMemoryInfo(memoryInfo);
    }
}
