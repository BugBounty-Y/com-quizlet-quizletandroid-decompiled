package com.google.android.gms.internal.ads;

import android.content.Context;

/* loaded from: classes2.dex */
public final /* synthetic */ class Fj implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.android.gms.ads.internal.client.zzr b;
    public final /* synthetic */ Vp c;
    public final /* synthetic */ Xp d;
    public final /* synthetic */ com.google.android.gms.ads.internal.a e;
    public final /* synthetic */ C1673Cc f;
    public final /* synthetic */ String g;
    public final /* synthetic */ String h;
    public final /* synthetic */ Object i;

    public /* synthetic */ Fj(Object obj, com.google.android.gms.ads.internal.client.zzr zzrVar, Vp vp, Xp xp, com.google.android.gms.ads.internal.a aVar, C1673Cc c1673Cc, String str, String str2, int i) {
        this.a = i;
        this.i = obj;
        this.b = zzrVar;
        this.c = vp;
        this.d = xp;
        this.e = aVar;
        this.f = c1673Cc;
        this.g = str;
        this.h = str2;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        switch (this.a) {
            case 0:
                Gj gj = (Gj) this.i;
                com.google.android.gms.ads.internal.client.zzr zzrVar = this.b;
                Vp vp = this.c;
                Xp xp = this.d;
                com.google.android.gms.ads.internal.a aVar = this.e;
                C1673Cc c1673Cc = this.f;
                String str = this.g;
                String str2 = this.h;
                InterfaceC2529qe interfaceC2529qeA = ((C2406nk) gj.j).a(zzrVar, vp, xp);
                C2257k6 c2257k6 = new C2257k6(interfaceC2529qeA);
                C1887bk c1887bk = ((C1974dk) gj.l).a;
                C1669Be c1669BeL = interfaceC2529qeA.L();
                C2601s7 c2601s7 = AbstractC2773w7.rd;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                c1669BeL.q(c1887bk, c1887bk, c1887bk, c1887bk, c1887bk, false, null, !((Boolean) rVar.c.a(c2601s7)).booleanValue() ? new com.google.android.gms.ads.internal.a((Context) gj.a, null) : aVar, null, true != ((Boolean) rVar.c.a(c2601s7)).booleanValue() ? null : c1673Cc, (C2107gm) gj.o, (C2584rr) gj.n, (Hk) gj.m, null, c1887bk, null, null, null, null);
                interfaceC2529qeA.O0("/getNativeAdViewSignals", AbstractC2346m9.s);
                interfaceC2529qeA.O0("/getNativeClickMeta", AbstractC2346m9.t);
                C1669Be c1669BeL2 = interfaceC2529qeA.L();
                synchronized (c1669BeL2.d) {
                    c1669BeL2.s = true;
                }
                interfaceC2529qeA.L().g = new Ts(c2257k6, 20);
                interfaceC2529qeA.w0(str, str2);
                return c2257k6;
            default:
                Oj oj = (Oj) this.i;
                InterfaceC2529qe interfaceC2529qeA2 = oj.c.a(this.b, this.c, this.d);
                C2257k6 c2257k62 = new C2257k6(interfaceC2529qeA2);
                C2023eq c2023eq = oj.a;
                com.google.android.gms.ads.internal.a aVar2 = this.e;
                zzbmg zzbmgVar = c2023eq.b;
                C1673Cc c1673Cc2 = this.f;
                if (zzbmgVar != null) {
                    oj.a(interfaceC2529qeA2, aVar2, c1673Cc2);
                    interfaceC2529qeA2.k0(new com.bumptech.glide.load.engine.cache.f(5, 0, 0));
                } else {
                    C1887bk c1887bk2 = oj.d.a;
                    C1669Be c1669BeL3 = interfaceC2529qeA2.L();
                    C2601s7 c2601s72 = AbstractC2773w7.rd;
                    com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
                    if (!((Boolean) rVar2.c.a(c2601s72)).booleanValue()) {
                        aVar2 = new com.google.android.gms.ads.internal.a(oj.e, null);
                    }
                    c1669BeL3.q(c1887bk2, c1887bk2, c1887bk2, c1887bk2, c1887bk2, false, null, aVar2, null, true != ((Boolean) rVar2.c.a(c2601s72)).booleanValue() ? null : c1673Cc2, oj.h, oj.g, oj.f, null, c1887bk2, null, null, null, null);
                    Oj.b(interfaceC2529qeA2);
                }
                interfaceC2529qeA2.L().g = new Kj(oj, interfaceC2529qeA2, c2257k62, 0);
                interfaceC2529qeA2.w0(this.g, this.h);
                return c2257k62;
        }
    }
}
