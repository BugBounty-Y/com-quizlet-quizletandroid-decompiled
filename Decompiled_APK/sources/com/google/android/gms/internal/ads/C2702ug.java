package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ug, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2702ug implements CC {
    public final /* synthetic */ int a;
    public final C2326lq b;

    public /* synthetic */ C2702ug(C2326lq c2326lq, int i) {
        this.a = i;
        this.b = c2326lq;
    }

    public Vp a() {
        Vp vp = (Vp) this.b.c;
        AbstractC1981ds.s(vp);
        return vp;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Vp vp = (Vp) this.b.c;
                AbstractC1981ds.s(vp);
                return vp;
            case 1:
                return (String) this.b.d;
            case 2:
                return this.b.l();
            default:
                C1849aq c1849aq = (C1849aq) this.b.b;
                AbstractC1981ds.s(c1849aq);
                return c1849aq;
        }
    }
}
