package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.yf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2873yf implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final CC c;
    public final CC d;
    public final HC e;
    public final HC f;
    public final HC g;

    public C2873yf(C1729Le c1729Le, C1741Ne c1741Ne, BC bc, C1735Me c1735Me, Tg tg, C1741Ne c1741Ne2) {
        this.a = 6;
        this.d = c1729Le;
        this.c = c1741Ne;
        this.b = bc;
        this.e = c1735Me;
        this.f = tg;
        this.g = c1741Ne2;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Context contextA = ((C1741Ne) this.c).a();
                com.google.android.gms.ads.internal.util.C cA = ((C1729Le) this.d).a();
                C2708um c2708um = (C2708um) this.b.zzb();
                C2535qk c2535qk = (C2535qk) ((BC) this.e).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2830xf(contextA, cA, c2708um, c2535qk, c2227jd, (Xv) ((BC) this.f).zzb(), (ScheduledExecutorService) ((BC) this.g).zzb());
            case 1:
                C1765Re c1765Re = (C1765Re) ((DC) this.c).a;
                Sg sgA = ((Tg) this.d).b.a();
                C1841ai c1841ai = (C1841ai) this.e;
                Gi gi = (Gi) this.f;
                Gh ghA = ((C1730Lf) this.g).a();
                C2195in c2195in = (C2195in) this.b.zzb();
                C1765Re c1765Re2 = c1765Re.b;
                Sg sg = new Sg(sgA);
                Ts ts = null;
                C2881yn c2881yn = new C2881yn(ts, 0);
                C1732Mb c1732Mb = new C1732Mb(16, ghA, ts);
                Os os = new Os(ts, 14);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L3)).booleanValue()) {
                    ts = new Ts();
                    ts.b = c2195in;
                }
                Zh zh = c1841ai.b;
                AbstractC1981ds.w(Zh.class, zh);
                if (ts == null) {
                    ts = new Ts();
                }
                Fi fi = gi.b;
                AbstractC1981ds.w(Fi.class, fi);
                InterfaceC2488pg interfaceC2488pg = (InterfaceC2488pg) new C1789Ve(c1765Re2, os, fi, new C2147hi(13, (byte) 0), zh, sg, ts, c2881yn, c1732Mb, null, null).s0.zzb();
                AbstractC1981ds.s(interfaceC2488pg);
                return interfaceC2488pg;
            case 2:
                Context contextA2 = ((C1741Ne) this.c).a();
                C2023eq c2023eqA = ((Tg) this.d).a();
                C1691Fc c1691Fc = (C1691Fc) this.g;
                C2227jd c2227jd2 = AbstractC2270kd.b;
                AbstractC1981ds.s(c2227jd2);
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(c2227jd2, c2227jd3, new El((Context) ((Ok) c1691Fc.b).b.zzb(), c2227jd3, 0), BC.a((com.google.android.gms.ads.nonagon.signalgeneration.t) c1691Fc.c));
                AbstractC1981ds.s(c2227jd3);
                return new Cl(contextA2, c2023eqA, aVar, c2227jd3, (ScheduledExecutorService) this.b.zzb(), (C1889bm) ((BC) this.e).zzb(), (Tq) ((BC) this.f).zzb());
            case 3:
                C1765Re c1765Re3 = (C1765Re) ((DC) this.c).a;
                Gi gi2 = (Gi) this.d;
                Sg sgA2 = ((Tg) this.f).b.a();
                C1841ai c1841ai2 = (C1841ai) this.g;
                return new C1933cn(c1765Re3, gi2.b, sgA2, c1841ai2.b, (C2195in) this.b.zzb(), (C2923zm) ((BC) this.e).zzb());
            case 4:
                C1765Re c1765Re4 = (C1765Re) ((DC) this.c).a;
                Sg sgA3 = ((Tg) this.d).b.a();
                C2924zn c2924zn = (C2924zn) this.f;
                C1841ai c1841ai3 = (C1841ai) this.g;
                return new C1933cn(c1765Re4, sgA3, c2924zn.b, c1841ai3.b, (C2195in) this.b.zzb(), (C2923zm) ((BC) this.e).zzb());
            case 5:
                C1765Re c1765Re5 = (C1765Re) ((DC) this.c).a;
                Sg sgA4 = ((Tg) this.d).b.a();
                C1841ai c1841ai4 = (C1841ai) this.f;
                return new C1933cn(c1765Re5, sgA4, c1841ai4.b, ((Tg) this.g).b.d, (C2195in) this.b.zzb(), (C2923zm) ((BC) this.e).zzb());
            case 6:
                com.google.android.gms.ads.internal.util.C cA2 = ((C1729Le) this.d).a();
                Context contextA3 = ((C1741Ne) this.c).a();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new C1935cp(cA2, contextA3, c2227jd4, (ScheduledExecutorService) this.b.zzb(), new Ts(((C1735Me) this.e).b.a(), 25), ((Tg) this.f).a(), ((C1741Ne) this.g).b());
            case 7:
                return new C2454op((Context) ((DC) this.c).a, (Executor) this.b.zzb(), (C1765Re) ((DC) this.d).a, ((Mm) this.f).a(), (C2411np) ((BC) this.e).zzb(), new C1979dq(), ((C1741Ne) this.g).b());
            case 8:
                return new Qp((Context) ((DC) this.c).a, (Executor) this.b.zzb(), (C1765Re) ((DC) this.d).a, ((Mm) this.g).a(), (Np) ((BC) this.e).zzb(), new C1979dq(), (C1893bq) ((BC) this.f).zzb());
            default:
                return new C2155hq((C2584rr) this.b.zzb(), (C2499pr) ((BC) this.e).zzb(), ((C2702ug) this.c).a(), ((C2702ug) this.d).b.l(), (C2830xf) ((BC) this.f).zzb(), (Tq) ((BC) this.g).zzb());
        }
    }

    public C2873yf(C1741Ne c1741Ne, C1729Le c1729Le, BC bc, BC bc2, BC bc3, BC bc4) {
        this.a = 0;
        this.c = c1741Ne;
        this.d = c1729Le;
        this.b = bc;
        this.e = bc2;
        this.f = bc3;
        this.g = bc4;
    }

    public C2873yf(C1741Ne c1741Ne, Tg tg, C1691Fc c1691Fc, BC bc, BC bc2, BC bc3) {
        this.a = 2;
        this.c = c1741Ne;
        this.d = tg;
        this.g = c1691Fc;
        this.b = bc;
        this.e = bc2;
        this.f = bc3;
    }

    public C2873yf(BC bc, BC bc2, C2702ug c2702ug, C2702ug c2702ug2, BC bc3, BC bc4) {
        this.a = 9;
        this.b = bc;
        this.e = bc2;
        this.c = c2702ug;
        this.d = c2702ug2;
        this.f = bc3;
        this.g = bc4;
    }

    public C2873yf(DC dc, Tg tg, C1841ai c1841ai, Gi gi, C1730Lf c1730Lf, BC bc) {
        this.a = 1;
        this.c = dc;
        this.d = tg;
        this.e = c1841ai;
        this.f = gi;
        this.g = c1730Lf;
        this.b = bc;
    }

    public C2873yf(DC dc, BC bc, DC dc2, Mm mm, BC bc2, C1741Ne c1741Ne) {
        this.a = 7;
        this.c = dc;
        this.b = bc;
        this.d = dc2;
        this.f = mm;
        this.e = bc2;
        this.g = c1741Ne;
    }

    public C2873yf(DC dc, BC bc, DC dc2, Mm mm, BC bc2, BC bc3) {
        this.a = 8;
        this.c = dc;
        this.b = bc;
        this.d = dc2;
        this.g = mm;
        this.e = bc2;
        this.f = bc3;
    }

    public /* synthetic */ C2873yf(DC dc, CC cc, CC cc2, CC cc3, BC bc, BC bc2, int i) {
        this.a = i;
        this.c = dc;
        this.d = cc;
        this.f = cc2;
        this.g = cc3;
        this.b = bc;
        this.e = bc2;
    }
}
