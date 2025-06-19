package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Pe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1753Pe implements CC {
    public final /* synthetic */ int a;
    public final DC b;

    public /* synthetic */ C1753Pe(DC dc, int i) {
        this.a = i;
        this.b = dc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                C1765Re c1765Re = (C1765Re) this.b.a;
                AbstractC1981ds.s(c1765Re);
                return c1765Re;
            case 1:
                return new S4((C2904z9) this.b.a, 19);
            case 2:
                return new C2881yn((C1813Ze) this.b.a, 24);
            case 3:
                return new Un((C2754vp) this.b.a, 3);
            default:
                return new To((Gp) this.b.a);
        }
    }
}
