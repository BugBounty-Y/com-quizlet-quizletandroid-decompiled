package com.google.android.gms.internal.ads;

import android.content.Context;

/* renamed from: com.google.android.gms.internal.ads.Jc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1715Jc implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final DC c;

    public /* synthetic */ C1715Jc(BC bc, DC dc, int i) {
        this.a = i;
        this.b = bc;
        this.c = dc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Fi(10, (com.google.android.gms.common.util.a) this.c.a, (C1697Gc) this.b.zzb());
            case 1:
                return new C2792wk((C2429o6) this.b.zzb(), (Gp) this.c.a);
            case 2:
                return new Qk((Nk) this.b.zzb(), (C1765Re) this.c.a);
            case 3:
                Context context = (Context) this.b.zzb();
                C1777Te c1777Te = (C1777Te) this.c.a;
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new Gm(context, c1777Te, c2227jd, 0);
            case 4:
                return new Im(0, (Context) this.b.zzb(), (C1777Te) this.c.a);
            case 5:
                return new Om((Context) this.b.zzb(), (C1789Ve) this.c.a);
            case 6:
                return new Im(1, (Context) this.b.zzb(), (C1813Ze) this.c.a);
            default:
                return new Im(2, (Context) this.b.zzb(), (C1882bf) this.c.a);
        }
    }

    public C1715Jc(DC dc, BC bc) {
        this.a = 0;
        this.c = dc;
        this.b = bc;
    }
}
