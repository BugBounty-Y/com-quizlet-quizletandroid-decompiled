package com.google.android.gms.internal.ads;

import java.util.List;

/* loaded from: classes2.dex */
public final class Ao implements CC {
    public final /* synthetic */ int a;
    public final C1735Me b;
    public final BC c;
    public final BC d;

    public /* synthetic */ Ao(C1735Me c1735Me, BC bc, BC bc2, int i) {
        this.a = i;
        this.b = c1735Me;
        this.c = bc;
        this.d = bc2;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Un un = new Un(this.b.b.a(), 0);
                com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) this.c.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2796wo(un, 2147483647L, aVar, c2227jd, (Hk) this.d.zzb());
            default:
                Object un2 = new Un(this.b.b.a(), 0);
                Object obj = (C2796wo) this.c.zzb();
                if (true == ((List) this.d.zzb()).contains("2")) {
                    un2 = obj;
                }
                AbstractC1981ds.s(un2);
                return un2;
        }
    }
}
