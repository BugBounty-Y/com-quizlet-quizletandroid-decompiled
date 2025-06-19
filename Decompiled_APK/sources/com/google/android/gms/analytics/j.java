package com.google.android.gms.analytics;

import android.content.Context;
import android.util.LogPrinter;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.gtm.zzau;
import java.lang.Thread;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes2.dex */
public final class j {
    public static volatile j e;
    public final Context a;
    public final g b;
    public volatile zzau c;
    public Thread.UncaughtExceptionHandler d;

    public j(Context context) {
        Context applicationContext = context.getApplicationContext();
        u.h(applicationContext);
        this.a = applicationContext;
        this.b = new g(this);
        new CopyOnWriteArrayList();
        new LogPrinter(4, "GA/LogCatTransport");
    }

    public static void a() {
        if (!(Thread.currentThread() instanceof i)) {
            throw new IllegalStateException("Call expected from worker thread");
        }
    }
}
