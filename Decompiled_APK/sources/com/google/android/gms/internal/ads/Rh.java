package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Rh implements Jh {
    public int a;
    public int b;

    @Override // com.google.android.gms.internal.ads.Jh
    public final synchronized void J0(C1849aq c1849aq) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.l1)).booleanValue()) {
            try {
                Xp xp = (Xp) c1849aq.b.b;
                this.a = xp.c;
                this.b = xp.d;
            } catch (NullPointerException unused) {
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
    }
}
