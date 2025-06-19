package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.il, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2193il implements CC {
    public final /* synthetic */ int a = 0;
    public final Tg b;
    public final BC c;
    public final BC d;

    public C2193il(Tg tg, BC bc, BC bc2) {
        this.b = tg;
        this.c = bc;
        this.d = bc2;
    }

    public C1891bo a() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        C2023eq c2023eqA = this.b.a();
        return new C1891bo(c2227jd, c2023eqA, ((Integer) this.d.zzb()).intValue());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                return new C2150hl((C2493pl) this.c.zzb(), this.b.a(), (String) this.d.zzb());
            default:
                return a();
        }
    }

    public C2193il(BC bc, Tg tg, BC bc2) {
        this.c = bc;
        this.b = tg;
        this.d = bc2;
    }
}
