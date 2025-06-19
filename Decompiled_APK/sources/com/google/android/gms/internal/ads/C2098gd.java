package com.google.android.gms.internal.ads;

import android.content.SharedPreferences;
import java.math.BigInteger;
import java.util.HashSet;

/* renamed from: com.google.android.gms.internal.ads.gd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2098gd implements L5 {
    public final com.google.android.gms.ads.internal.util.C b;
    public final C1732Mb c;
    public final C2054fd d;
    public final Object a = new Object();
    public final HashSet e = new HashSet();
    public final HashSet f = new HashSet();
    public boolean g = false;

    public C2098gd(String str, com.google.android.gms.ads.internal.util.C c) {
        this.d = new C2054fd(str, c);
        this.b = c;
        C1732Mb c1732Mb = new C1732Mb(12);
        c1732Mb.b = BigInteger.ONE;
        c1732Mb.c = "0";
        this.c = c1732Mb;
    }

    @Override // com.google.android.gms.internal.ads.L5
    public final void V(boolean z) {
        long j;
        int i;
        com.google.android.gms.ads.internal.j.C.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (z) {
            com.google.android.gms.ads.internal.util.C c = this.b;
            c.l();
            synchronized (c.a) {
                j = c.o;
            }
            if (jCurrentTimeMillis - j > ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Y0)).longValue()) {
                this.d.d = -1;
            } else {
                C2054fd c2054fd = this.d;
                c.l();
                synchronized (c.a) {
                    i = c.q;
                }
                c2054fd.d = i;
            }
            this.g = true;
            return;
        }
        com.google.android.gms.ads.internal.util.C c2 = this.b;
        c2.l();
        synchronized (c2.a) {
            try {
                if (c2.o != jCurrentTimeMillis) {
                    c2.o = jCurrentTimeMillis;
                    SharedPreferences.Editor editor = c2.g;
                    if (editor != null) {
                        editor.putLong("app_last_background_time_ms", jCurrentTimeMillis);
                        c2.g.apply();
                    }
                    c2.m();
                }
            } finally {
            }
        }
        int i2 = this.d.d;
        c2.l();
        synchronized (c2.a) {
            try {
                if (c2.q == i2) {
                    return;
                }
                c2.q = i2;
                SharedPreferences.Editor editor2 = c2.g;
                if (editor2 != null) {
                    editor2.putInt("request_in_session_count", i2);
                    c2.g.apply();
                }
                c2.m();
            } finally {
            }
        }
    }

    public final void a(C1880bd c1880bd) {
        synchronized (this.a) {
            this.e.add(c1880bd);
        }
    }
}
