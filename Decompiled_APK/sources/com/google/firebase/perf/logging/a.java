package com.google.firebase.perf.logging;

import android.util.Log;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class a {
    public static volatile a c;
    public final b a;
    public boolean b = false;

    public a() {
        b bVar;
        synchronized (b.class) {
            try {
                if (b.b == null) {
                    b.b = new b(0);
                }
                bVar = b.b;
            } catch (Throwable th) {
                throw th;
            }
        }
        this.a = bVar;
    }

    public static a d() {
        if (c == null) {
            synchronized (a.class) {
                try {
                    if (c == null) {
                        c = new a();
                    }
                } finally {
                }
            }
        }
        return c;
    }

    public final void a() {
        if (this.b) {
            this.a.getClass();
        }
    }

    public final void b(String str, Object... objArr) {
        if (this.b) {
            String.format(Locale.ENGLISH, str, objArr);
            this.a.getClass();
        }
    }

    public final void c(String str, Object... objArr) {
        if (this.b) {
            String str2 = String.format(Locale.ENGLISH, str, objArr);
            this.a.getClass();
            Log.e("FirebasePerformance", str2);
        }
    }

    public final void e(String str, Object... objArr) {
        if (this.b) {
            String str2 = String.format(Locale.ENGLISH, str, objArr);
            this.a.getClass();
            Log.i("FirebasePerformance", str2);
        }
    }

    public final void f(String str) {
        if (this.b) {
            this.a.getClass();
            Log.w("FirebasePerformance", str);
        }
    }

    public final void g(String str, Object... objArr) {
        if (this.b) {
            String str2 = String.format(Locale.ENGLISH, str, objArr);
            this.a.getClass();
            Log.w("FirebasePerformance", str2);
        }
    }
}
