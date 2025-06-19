package com.facebook.appevents.internal;

import android.app.Application;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import java.lang.ref.WeakReference;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public static final String a;
    public static final ScheduledExecutorService b;
    public static final ScheduledExecutorService c;
    public static volatile ScheduledFuture d;
    public static final Object e;
    public static final AtomicInteger f;
    public static volatile androidx.navigation.internal.m g;
    public static final AtomicBoolean h;
    public static String i;
    public static long j;
    public static int k;
    public static WeakReference l;
    public static String m;

    static {
        String canonicalName = c.class.getCanonicalName();
        if (canonicalName == null) {
            canonicalName = "com.facebook.appevents.internal.ActivityLifecycleTracker";
        }
        a = canonicalName;
        b = Executors.newSingleThreadScheduledExecutor();
        c = Executors.newSingleThreadScheduledExecutor();
        e = new Object();
        f = new AtomicInteger(0);
        h = new AtomicBoolean(false);
    }

    public static void a() {
        ScheduledFuture scheduledFuture;
        synchronized (e) {
            try {
                if (d != null && (scheduledFuture = d) != null) {
                    scheduledFuture.cancel(false);
                }
                d = null;
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final UUID b() {
        androidx.navigation.internal.m mVar;
        if (g == null || (mVar = g) == null) {
            return null;
        }
        return (UUID) mVar.e;
    }

    public static final void c(Application application, String str) {
        Intrinsics.checkNotNullParameter(application, "application");
        if (h.compareAndSet(false, true)) {
            C1563s.a(new com.facebook.appevents.k(12), EnumC1562q.CodelessEvents);
            i = str;
            application.registerActivityLifecycleCallbacks(new b(0));
        }
    }
}
