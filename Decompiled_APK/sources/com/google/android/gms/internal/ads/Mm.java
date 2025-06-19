package com.google.android.gms.internal.ads;

import android.content.Context;

/* loaded from: classes2.dex */
public final class Mm implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final DC c;
    public final BC d;

    public /* synthetic */ Mm(BC bc, BC bc2, DC dc, int i) {
        this.a = i;
        this.b = bc;
        this.d = bc2;
        this.c = dc;
    }

    public Ep a() {
        C1923cd c1923cdN;
        C1923cd c1923cdN2;
        switch (this.a) {
            case 4:
                Context context = (Context) this.c.a;
                C2498pq c2498pq = (C2498pq) this.b.zzb();
                Aq aq = (Aq) this.d.zzb();
                C2601s7 c2601s7 = AbstractC2773w7.l6;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    c1923cdN = com.google.android.gms.ads.internal.j.C.h.d().n();
                } else {
                    com.google.android.gms.ads.internal.util.C cD = com.google.android.gms.ads.internal.j.C.h.d();
                    synchronized (cD.a) {
                        c1923cdN = cD.n;
                    }
                }
                boolean z = false;
                if (c1923cdN != null && c1923cdN.j) {
                    z = true;
                }
                if (((Integer) rVar.c.a(AbstractC2773w7.B6)).intValue() > 0) {
                    if (!((Boolean) rVar.c.a(AbstractC2773w7.k6)).booleanValue() || z) {
                        C2927zq c2927zqA = aq.a(EnumC2712uq.c, context, c2498pq, new Os(new C2881yn(26), 27));
                        Fi fi = new Fi(new C2883yp(0, (byte) 0));
                        C2227jd c2227jd = AbstractC2270kd.a;
                        C2326lq c2326lq = c2927zqA.a;
                        return new C2084g6(fi, new C2326lq(c2326lq, c2227jd), c2927zqA.b, ((zzfej) c2326lq.c).g, c2227jd);
                    }
                }
                return new C2883yp(0, (byte) 0);
            default:
                Context context2 = (Context) this.c.a;
                C2498pq c2498pq2 = (C2498pq) this.b.zzb();
                Aq aq2 = (Aq) this.d.zzb();
                C2601s7 c2601s72 = AbstractC2773w7.l6;
                com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar2.c.a(c2601s72)).booleanValue()) {
                    c1923cdN2 = com.google.android.gms.ads.internal.j.C.h.d().n();
                } else {
                    com.google.android.gms.ads.internal.util.C cD2 = com.google.android.gms.ads.internal.j.C.h.d();
                    synchronized (cD2.a) {
                        c1923cdN2 = cD2.n;
                    }
                }
                boolean z2 = false;
                if (c1923cdN2 != null && c1923cdN2.j) {
                    z2 = true;
                }
                if (((Integer) rVar2.c.a(AbstractC2773w7.n6)).intValue() > 0) {
                    if (!((Boolean) rVar2.c.a(AbstractC2773w7.k6)).booleanValue() || z2) {
                        C2927zq c2927zqA2 = aq2.a(EnumC2712uq.a, context2, c2498pq2, new Os(new C2881yn(26), 27));
                        Fi fi2 = new Fi(new C2883yp(0, (byte) 0));
                        C2227jd c2227jd2 = AbstractC2270kd.a;
                        C2326lq c2326lq2 = c2927zqA2.a;
                        return new C2084g6(fi2, new C2326lq(c2326lq2, c2227jd2), c2927zqA2.b, ((zzfej) c2326lq2.c).g, c2227jd2);
                    }
                }
                return new C2883yp(0, (byte) 0);
        }
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
        }
        return a();
    }

    public /* synthetic */ Mm(BC bc, DC dc, BC bc2, int i) {
        this.a = i;
        this.b = bc;
        this.c = dc;
        this.d = bc2;
    }

    public /* synthetic */ Mm(DC dc, BC bc, BC bc2, int i) {
        this.a = i;
        this.c = dc;
        this.b = bc;
        this.d = bc2;
    }
}
