package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.bD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1873bD implements Pk {
    public final /* synthetic */ int a;
    public final /* synthetic */ GD b;

    public /* synthetic */ C1873bD(GD gd, int i) {
        this.a = 0;
        this.b = gd;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public final void mo10b(Object obj) {
        C2093gF c2093gF;
        GD gd = this.b;
        WD wd = (WD) obj;
        switch (this.a) {
            case 0:
                int i = C2221jD.i1;
                A9 a9 = gd.a;
                PD pd = wd.g;
                pd.getClass();
                C2084g6 c2084g6 = wd.d;
                c2084g6.d = C2084g6.t(pd, (AbstractC2330lu) c2084g6.b, (C2093gF) c2084g6.e, (C2303l9) c2084g6.a);
                c2084g6.w(pd.h1());
                wd.i(wd.g(), 0, new C2047fD(12));
                break;
            case 1:
                int i2 = C2221jD.i1;
                boolean z = gd.l;
                wd.i(wd.g(), 5, new C2047fD(26));
                break;
            default:
                int i3 = C2221jD.i1;
                zzik zzikVar = gd.f;
                wd.getClass();
                RD rdG = (zzikVar == null || (c2093gF = zzikVar.h) == null) ? wd.g() : wd.j(c2093gF);
                wd.i(rdG, 10, new C2586rt(rdG, zzikVar));
                break;
        }
    }

    public /* synthetic */ C1873bD(GD gd, int i, byte b) {
        this.a = i;
        this.b = gd;
    }
}
