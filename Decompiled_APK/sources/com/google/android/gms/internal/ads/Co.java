package com.google.android.gms.internal.ads;

import java.util.List;

/* loaded from: classes2.dex */
public final class Co implements CC {
    public final /* synthetic */ int a;
    public final K7 b;
    public final BC c;
    public final BC d;

    public /* synthetic */ Co(K7 k7, BC bc, BC bc2, int i) {
        this.a = i;
        this.b = k7;
        this.c = bc;
        this.d = bc2;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                C2021eo c2021eoA = this.b.a();
                com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) this.c.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2796wo(c2021eoA, 2147483647L, aVar, c2227jd, (Hk) this.d.zzb());
            default:
                Object objA = this.b.a();
                Object obj = (C2796wo) this.c.zzb();
                if (true == ((List) this.d.zzb()).contains("29")) {
                    objA = obj;
                }
                AbstractC1981ds.s(objA);
                return objA;
        }
    }
}
