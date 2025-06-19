package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Gc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1697Gc {
    public final com.google.android.gms.ads.internal.util.C a;

    public C1697Gc(com.google.android.gms.ads.internal.util.C c) {
        this.a = c;
    }

    public final void a(int i, long j) {
        long j2;
        C2601s7 c2601s7 = AbstractC2773w7.y0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            return;
        }
        com.google.android.gms.ads.internal.util.C c = this.a;
        c.l();
        synchronized (c.a) {
            j2 = c.D;
        }
        if (j - j2 < 0) {
            com.google.android.gms.ads.internal.util.A.l("Receiving npa decision in the past, ignoring.");
            return;
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.z0)).booleanValue()) {
            c.f(i);
            c.g(j);
        } else {
            c.f(-1);
            c.g(j);
        }
    }
}
