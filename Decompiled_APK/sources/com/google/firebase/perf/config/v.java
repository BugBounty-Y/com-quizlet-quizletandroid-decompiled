package com.google.firebase.perf.config;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes2.dex */
public final class v {
    public static final com.google.firebase.perf.logging.a c = com.google.firebase.perf.logging.a.d();
    public static v d;
    public volatile SharedPreferences a;
    public final ExecutorService b;

    public v(ExecutorService executorService) {
        this.b = executorService;
    }

    public static Context a() {
        try {
            com.google.firebase.h.c();
            com.google.firebase.h hVarC = com.google.firebase.h.c();
            hVarC.a();
            return hVarC.a;
        } catch (IllegalStateException unused) {
            return null;
        }
    }

    public static synchronized v b() {
        try {
            if (d == null) {
                d = new v(Executors.newSingleThreadExecutor());
            }
        } catch (Throwable th) {
            throw th;
        }
        return d;
    }

    public final synchronized void c(Context context) {
        if (this.a == null && context != null) {
            this.b.execute(new com.google.firebase.crashlytics.internal.common.i(6, this, context));
        }
    }

    public final void d(long j, String str) {
        if (this.a == null) {
            c(a());
            if (this.a == null) {
                return;
            }
        }
        this.a.edit().putLong(str, j).apply();
    }

    public final void e(String str, double d2) {
        if (this.a == null) {
            c(a());
            if (this.a == null) {
                return;
            }
        }
        this.a.edit().putLong(str, Double.doubleToRawLongBits(d2)).apply();
    }

    public final void f(String str, String str2) {
        if (this.a == null) {
            c(a());
            if (this.a == null) {
                return;
            }
        }
        if (str2 == null) {
            this.a.edit().remove(str).apply();
        } else {
            this.a.edit().putString(str, str2).apply();
        }
    }

    public final void g(String str, boolean z) {
        if (this.a == null) {
            c(a());
            if (this.a == null) {
                return;
            }
        }
        assistantMode.refactored.a.p(this.a, str, z);
    }
}
