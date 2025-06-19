package com.google.android.gms.measurement.internal;

import android.os.Handler;
import com.google.android.gms.internal.ads.Ls;

/* renamed from: com.google.android.gms.measurement.internal.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3876k {
    public static volatile Ls d;
    public final InterfaceC3873i0 a;
    public final com.google.common.util.concurrent.d b;
    public volatile long c;

    public AbstractC3876k(InterfaceC3873i0 interfaceC3873i0) {
        com.google.android.gms.common.internal.u.h(interfaceC3873i0);
        this.a = interfaceC3873i0;
        this.b = new com.google.common.util.concurrent.d(this, false, interfaceC3873i0, 24);
    }

    public final void a() {
        this.c = 0L;
        d().removeCallbacks(this.b);
    }

    public abstract void b();

    public final void c(long j) {
        a();
        if (j >= 0) {
            InterfaceC3873i0 interfaceC3873i0 = this.a;
            this.c = interfaceC3873i0.f().currentTimeMillis();
            if (d().postDelayed(this.b, j)) {
                return;
            }
            interfaceC3873i0.c().g.g("Failed to schedule delayed post. time", Long.valueOf(j));
        }
    }

    public final Handler d() {
        Ls ls;
        if (d != null) {
            return d;
        }
        synchronized (AbstractC3876k.class) {
            try {
                if (d == null) {
                    d = new Ls(this.a.d().getMainLooper(), 4);
                }
                ls = d;
            } catch (Throwable th) {
                throw th;
            }
        }
        return ls;
    }
}
