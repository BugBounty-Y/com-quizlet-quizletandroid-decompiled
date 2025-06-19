package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import android.content.pm.PackageInfo;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.Bi;
import com.google.android.gms.internal.ads.C1691Fc;
import com.google.android.gms.internal.ads.C1700Gf;
import com.google.android.gms.internal.ads.C1706Hf;
import com.google.android.gms.internal.ads.C1724Kf;
import com.google.android.gms.internal.ads.C1727Lc;
import com.google.android.gms.internal.ads.C1729Le;
import com.google.android.gms.internal.ads.C1735Me;
import com.google.android.gms.internal.ads.C1739Nc;
import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.C1747Oe;
import com.google.android.gms.internal.ads.C1753Pe;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1784Uf;
import com.google.android.gms.internal.ads.C1789Ve;
import com.google.android.gms.internal.ads.C1802Xf;
import com.google.android.gms.internal.ads.C1813Ze;
import com.google.android.gms.internal.ads.C1839ag;
import com.google.android.gms.internal.ads.C1841ai;
import com.google.android.gms.internal.ads.C1889bm;
import com.google.android.gms.internal.ads.C1929cj;
import com.google.android.gms.internal.ads.C1969df;
import com.google.android.gms.internal.ads.C1976dm;
import com.google.android.gms.internal.ads.C1979dq;
import com.google.android.gms.internal.ads.C2020en;
import com.google.android.gms.internal.ads.C2022ep;
import com.google.android.gms.internal.ads.C2101gg;
import com.google.android.gms.internal.ads.C2146hh;
import com.google.android.gms.internal.ads.C2195in;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2239jp;
import com.google.android.gms.internal.ads.C2283kq;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.C2429o6;
import com.google.android.gms.internal.ads.C2472p6;
import com.google.android.gms.internal.ads.C2482pa;
import com.google.android.gms.internal.ads.C2499pr;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2620sk;
import com.google.android.gms.internal.ads.C2622sm;
import com.google.android.gms.internal.ads.C2702ug;
import com.google.android.gms.internal.ads.C2790wi;
import com.google.android.gms.internal.ads.C2923zm;
import com.google.android.gms.internal.ads.C2924zn;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.Ch;
import com.google.android.gms.internal.ads.Ck;
import com.google.android.gms.internal.ads.D7;
import com.google.android.gms.internal.ads.DC;
import com.google.android.gms.internal.ads.Di;
import com.google.android.gms.internal.ads.EC;
import com.google.android.gms.internal.ads.Ei;
import com.google.android.gms.internal.ads.EnumC2515q6;
import com.google.android.gms.internal.ads.G6;
import com.google.android.gms.internal.ads.Gi;
import com.google.android.gms.internal.ads.Gn;
import com.google.android.gms.internal.ads.H6;
import com.google.android.gms.internal.ads.HC;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.Kg;
import com.google.android.gms.internal.ads.Kp;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.Ln;
import com.google.android.gms.internal.ads.Lq;
import com.google.android.gms.internal.ads.Np;
import com.google.android.gms.internal.ads.Os;
import com.google.android.gms.internal.ads.Qm;
import com.google.android.gms.internal.ads.Tg;
import com.google.android.gms.internal.ads.Tl;
import com.google.android.gms.internal.ads.Ts;
import com.google.android.gms.internal.ads.Ug;
import com.google.android.gms.internal.ads.Up;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Xv;
import com.google.android.gms.internal.ads.Yv;
import com.google.android.gms.internal.ads.zzbvl;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class t implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final HC c;
    public final HC d;
    public final HC e;
    public final Object f;

    public t(C1741Ne c1741Ne, j jVar, BC bc, C1691Fc c1691Fc, C1729Le c1729Le) {
        this.a = 10;
        this.f = c1741Ne;
        this.c = jVar;
        this.b = bc;
        this.d = c1691Fc;
        this.e = c1729Le;
    }

    public Ug a() {
        return new Ug(((C2702ug) this.f).a(), (String) ((C2702ug) this.d).b.d, (C2923zm) this.b.zzb(), ((C2702ug) this.e).b.l(), (String) ((BC) this.c).zzb());
    }

    public C1976dm b() {
        return new C1976dm(((C1741Ne) this.f).a(), ((j) this.c).a(), (C1889bm) this.b.zzb(), ((C1691Fc) this.d).a(), ((C1729Le) this.e).a());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new k(((C1741Ne) this.f).a(), ((Long) this.b.zzb()).longValue(), (PackageInfo) ((BC) this.c).zzb(), (u) ((BC) this.d).zzb(), (ScheduledExecutorService) ((BC) this.e).zzb());
            case 1:
                return new C1724Kf((C2482pa) this.b.zzb(), (C1706Hf) ((BC) this.c).zzb(), (Executor) ((BC) this.d).zzb(), (C1700Gf) ((BC) this.e).zzb(), (com.google.android.gms.common.util.a) ((BC) this.f).zzb());
            case 2:
                return new C2101gg(((C1741Ne) this.f).a(), (InterfaceC2529qe) ((C1802Xf) this.c).b.d, ((C2702ug) this.d).a(), ((C1741Ne) this.e).b(), (C2622sm) this.b.zzb());
            case 3:
                C2146hh c2146hh = (C2146hh) this.b.zzb();
                Vp vpA = ((C2702ug) this.f).a();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) ((BC) this.c).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new Kg(c2146hh, vpA, scheduledExecutorService, c2227jd, (String) ((C2702ug) this.e).b.d, (Ch) ((BC) this.d).zzb());
            case 4:
                return a();
            case 5:
                return new Bi(((C1741Ne) this.f).a(), (InterfaceC2529qe) ((C2790wi) this.c).b.c, ((C2702ug) this.d).a(), ((C1741Ne) this.e).b(), (C2622sm) this.b.zzb());
            case 6:
                C1839ag c1839ag = (C1839ag) this.c;
                C1727Lc c1727Lc = new C1727Lc(c1839ag.b.a(), c1839ag.c.a().f);
                Context contextA = ((C1741Ne) this.f).a();
                C1739Nc c1739Nc = (C1739Nc) this.b.zzb();
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) ((C2790wi) this.d).b.c;
                return new Di(c1727Lc, contextA, c1739Nc, interfaceC2529qe == null ? null : interfaceC2529qe.n(), (EnumC2515q6) ((CC) this.e).zzb());
            case 7:
                Map mapZzb = ((EC) this.f).zzb();
                Map mapZzb2 = ((EC) this.c).zzb();
                Map mapZzb3 = ((EC) this.d).zzb();
                C1929cj c1929cj = (C1929cj) ((Gi) this.e).b.b;
                AbstractC1981ds.s(c1929cj);
                return new Ei(mapZzb, mapZzb2, mapZzb3, this.b, c1929cj);
            case 8:
                Context contextA2 = ((C1741Ne) this.f).a();
                String packageName = ((C1735Me) this.c).b.a().getPackageName();
                AbstractC1981ds.s(packageName);
                VersionInfoParcel versionInfoParcelB = ((C1741Ne) this.d).b();
                EnumC2515q6 enumC2515q6 = (EnumC2515q6) this.e.zzb();
                String str = (String) this.b.zzb();
                C2429o6 c2429o6 = new C2429o6(new C2472p6(contextA2));
                G6 g6Z = H6.z();
                int i = versionInfoParcelB.b;
                g6Z.e();
                H6.w((H6) g6Z.b, i);
                int i2 = versionInfoParcelB.c;
                g6Z.e();
                H6.y((H6) g6Z.b, i2);
                int i3 = true != versionInfoParcelB.d ? 2 : 0;
                g6Z.e();
                H6.x((H6) g6Z.b, i3);
                H6 h6 = (H6) g6Z.c();
                com.quizlet.data.repository.explanations.question.a aVar = new com.quizlet.data.repository.explanations.question.a();
                aVar.a = enumC2515q6;
                aVar.b = packageName;
                aVar.c = h6;
                aVar.d = str;
                c2429o6.a(aVar);
                return c2429o6;
            case 9:
                Context contextA3 = ((C1741Ne) this.f).a();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                L9 l9 = new L9(15);
                C1765Re c1765Re = (C1765Re) ((C1753Pe) this.d).b.a;
                AbstractC1981ds.s(c1765Re);
                return new Tl(contextA3, c2227jd2, l9, c1765Re, new Os(((C1747Oe) ((C1969df) this.e).b).b(), 22), (ArrayDeque) this.b.zzb(), (Uq) ((BC) this.c).zzb());
            case 10:
                return b();
            case 11:
                return new C2622sm(((C1741Ne) this.f).a(), ((C1741Ne) this.c).b(), ((C2702ug) this.d).a(), (InterfaceC2529qe) ((CC) this.e).zzb(), (Hk) this.b.zzb());
            case 12:
                return new Qm((Context) this.b.zzb(), (Executor) ((BC) this.c).zzb(), (C1813Ze) ((DC) this.f).a, (Up) ((BC) this.d).zzb(), (Hk) ((BC) this.e).zzb());
            case 13:
                return new C2020en((C1765Re) ((DC) this.f).a, ((Tg) this.d).b.a(), ((C1841ai) this.e).b, (C2195in) this.b.zzb(), (C2923zm) ((BC) this.c).zzb());
            case 14:
                com.google.android.gms.common.util.a aVar2 = (com.google.android.gms.common.util.a) this.b.zzb();
                Ck ck = (Ck) this.e;
                C2326lq c2326lq = new C2326lq(21, (C2283kq) ck.b.zzb(), (C2620sk) ck.c.zzb(), (Hk) ck.d.zzb(), false);
                C2923zm c2923zm = (C2923zm) ((BC) this.c).zzb();
                C2584rr c2584rr = (C2584rr) ((BC) this.d).zzb();
                C2195in c2195in = (C2195in) ((Ts) this.f).b;
                return c2195in != null ? c2195in : new C2195in(aVar2, c2326lq, c2923zm, c2584rr);
            case 15:
                return new Qm((Context) this.b.zzb(), (C1789Ve) ((DC) this.f).a, (Lq) ((BC) this.c).zzb(), (Xv) ((BC) this.d).zzb(), (D7) ((C2924zn) this.e).b.b);
            case 16:
                return new Gn((Context) this.b.zzb(), (InterfaceC1622x) ((Gi) this.f).b.c, ((Tg) this.d).a(), ((C1784Uf) ((C1969df) this.e).b).a(), (Hk) ((BC) this.c).zzb());
            case 17:
                L9 l92 = new L9(18);
                Context contextA4 = ((C1741Ne) this.f).a();
                ScheduledExecutorService scheduledExecutorService2 = (ScheduledExecutorService) this.b.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                return new C2022ep(l92, contextA4, scheduledExecutorService2, c2227jd3, ((C2239jp) this.c).b.b, ((zzbvl) ((C2239jp) this.d).b.c).l, ((zzbvl) ((C2239jp) this.e).b.c).k);
            case 18:
                return new Kp((Context) ((DC) this.f).a, (Executor) this.b.zzb(), (C1765Re) ((DC) this.e).a, (Ln) ((BC) this.c).zzb(), (Np) ((BC) this.d).zzb(), new C1979dq());
            default:
                Context contextA5 = ((C1741Ne) this.f).a();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new C2584rr(contextA5, c2227jd4, (Yv) this.b.zzb(), (com.google.android.gms.ads.internal.util.client.k) this.e.zzb(), (C2499pr) ((BC) this.c).zzb(), (Uq) ((BC) this.d).zzb());
        }
    }

    public /* synthetic */ t(C1741Ne c1741Ne, BC bc, HC hc, HC hc2, HC hc3, int i) {
        this.a = i;
        this.f = c1741Ne;
        this.b = bc;
        this.c = hc;
        this.d = hc2;
        this.e = hc3;
    }

    public /* synthetic */ t(C1741Ne c1741Ne, CC cc, CC cc2, HC hc, BC bc, int i) {
        this.a = i;
        this.f = c1741Ne;
        this.c = cc;
        this.d = cc2;
        this.e = hc;
        this.b = bc;
    }

    public t(C1839ag c1839ag, C1741Ne c1741Ne, BC bc, C2790wi c2790wi, CC cc) {
        this.a = 6;
        this.c = c1839ag;
        this.f = c1741Ne;
        this.b = bc;
        this.d = c2790wi;
        this.e = cc;
    }

    public t(C2702ug c2702ug, C2702ug c2702ug2, BC bc, C2702ug c2702ug3, BC bc2) {
        this.a = 4;
        this.f = c2702ug;
        this.d = c2702ug2;
        this.b = bc;
        this.e = c2702ug3;
        this.c = bc2;
    }

    public t(BC bc, C2702ug c2702ug, BC bc2, C2702ug c2702ug2, BC bc3) {
        this.a = 3;
        this.b = bc;
        this.f = c2702ug;
        this.c = bc2;
        this.e = c2702ug2;
        this.d = bc3;
    }

    public t(BC bc, Gi gi, Tg tg, C1969df c1969df, BC bc2) {
        this.a = 16;
        this.b = bc;
        this.f = gi;
        this.d = tg;
        this.e = c1969df;
        this.c = bc2;
    }

    public t(BC bc, BC bc2, BC bc3, BC bc4, BC bc5) {
        this.a = 1;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.e = bc4;
        this.f = bc5;
    }

    public t(BC bc, BC bc2, DC dc, BC bc3, BC bc4) {
        this.a = 12;
        this.b = bc;
        this.c = bc2;
        this.f = dc;
        this.d = bc3;
        this.e = bc4;
    }

    public t(BC bc, DC dc, BC bc2, BC bc3, C2924zn c2924zn) {
        this.a = 15;
        this.b = bc;
        this.f = dc;
        this.c = bc2;
        this.d = bc3;
        this.e = c2924zn;
    }

    public /* synthetic */ t(CC cc, CC cc2, CC cc3, BC bc, BC bc2, int i) {
        this.a = i;
        this.f = cc;
        this.d = cc2;
        this.e = cc3;
        this.b = bc;
        this.c = bc2;
    }

    public t(EC ec, EC ec2, EC ec3, BC bc, Gi gi) {
        this.a = 7;
        this.f = ec;
        this.c = ec2;
        this.d = ec3;
        this.b = bc;
        this.e = gi;
    }

    public /* synthetic */ t(Object obj, BC bc, HC hc, BC bc2, BC bc3, int i) {
        this.a = i;
        this.f = obj;
        this.b = bc;
        this.e = hc;
        this.c = bc2;
        this.d = bc3;
    }
}
