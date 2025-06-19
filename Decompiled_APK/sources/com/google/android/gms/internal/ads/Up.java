package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Up {
    public final com.google.android.gms.common.util.a a;
    public final Hk b;
    public final Object c = new Object();
    public volatile int e = 1;
    public volatile long d = 0;

    public Up(com.google.android.gms.common.util.a aVar, Hk hk) {
        this.a = aVar;
        this.b = hk;
    }

    public final void a(boolean z) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Xc)).booleanValue()) {
            Fi fiA = this.b.a();
            fiA.o("action", "mbs_state");
            fiA.o("mbs_state", true != z ? "0" : "1");
            fiA.x();
        }
        if (z) {
            c(1, 2);
        } else {
            c(2, 1);
        }
    }

    public final void b() {
        long jCurrentTimeMillis = this.a.currentTimeMillis();
        synchronized (this.c) {
            try {
                if (this.e == 3) {
                    if (this.d + ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U5)).longValue() <= jCurrentTimeMillis) {
                        this.e = 1;
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void c(int i, int i2) {
        b();
        Object obj = this.c;
        long jCurrentTimeMillis = this.a.currentTimeMillis();
        synchronized (obj) {
            try {
                if (this.e != i) {
                    return;
                }
                this.e = i2;
                if (this.e == 3) {
                    this.d = jCurrentTimeMillis;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
