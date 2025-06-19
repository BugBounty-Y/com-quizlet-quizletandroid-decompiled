package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zzm;

/* renamed from: com.google.android.gms.internal.ads.fd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2054fd {
    public final String g;
    public final com.google.android.gms.ads.internal.util.C h;
    public long a = -1;
    public long b = -1;
    public int c = -1;
    public int d = -1;
    public long e = 0;
    public final Object f = new Object();
    public int i = 0;
    public int j = 0;
    public int k = 0;

    public C2054fd(String str, com.google.android.gms.ads.internal.util.C c) {
        this.g = str;
        this.h = c;
    }

    public final void a(zzm zzmVar, long j) {
        long j2;
        long j3;
        Bundle bundle;
        int i;
        synchronized (this.f) {
            try {
                com.google.android.gms.ads.internal.util.C c = this.h;
                c.l();
                synchronized (c.a) {
                    j2 = c.o;
                }
                com.google.android.gms.ads.internal.j.C.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (this.b == -1) {
                    if (jCurrentTimeMillis - j2 > ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Y0)).longValue()) {
                        this.d = -1;
                    } else {
                        c.l();
                        synchronized (c.a) {
                            i = c.q;
                        }
                        this.d = i;
                    }
                    this.b = j;
                    this.a = j;
                } else {
                    this.a = j;
                }
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J3)).booleanValue() || (bundle = zzmVar.c) == null || bundle.getInt("gw", 2) != 1) {
                    this.c++;
                    int i2 = this.d + 1;
                    this.d = i2;
                    if (i2 == 0) {
                        this.e = 0L;
                        c.t(jCurrentTimeMillis);
                    } else {
                        c.l();
                        synchronized (c.a) {
                            j3 = c.p;
                        }
                        this.e = jCurrentTimeMillis - j3;
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        if (((Boolean) AbstractC1998e8.a.o()).booleanValue()) {
            synchronized (this.f) {
                this.c--;
                this.d--;
            }
        }
    }
}
