package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.Uf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1784Uf implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;
    public final BC d;
    public final HC e;
    public final HC f;
    public final HC g;
    public final HC h;
    public final HC i;
    public final HC j;
    public final HC k;

    public C1784Uf(com.google.android.gms.ads.nonagon.signalgeneration.n nVar, BC bc, C1802Xf c1802Xf, C1802Xf c1802Xf2, C1802Xf c1802Xf3, C1802Xf c1802Xf4, Gi gi, BC bc2, C2153ho c2153ho, BC bc3) {
        this.a = 0;
        this.e = nVar;
        this.b = bc;
        this.f = c1802Xf;
        this.g = c1802Xf2;
        this.h = c1802Xf3;
        this.i = c1802Xf4;
        this.j = gi;
        this.c = bc2;
        this.k = c2153ho;
        this.d = bc3;
    }

    public C1778Tf a() {
        com.google.android.datatransport.cct.internal.s sVarA = ((com.google.android.gms.ads.nonagon.signalgeneration.n) this.e).a();
        Context context = (Context) this.b.zzb();
        Wp wp = (Wp) ((C1802Xf) this.f).b.c;
        AbstractC1981ds.s(wp);
        View view = (View) ((C1802Xf) this.g).b.b;
        AbstractC1981ds.s(view);
        com.google.firebase.messaging.u uVar = ((C1802Xf) this.h).b;
        InterfaceC2316lg interfaceC2316lg = (InterfaceC2316lg) ((C1802Xf) this.i).b.a;
        C1929cj c1929cj = (C1929cj) ((Gi) this.j).b.b;
        AbstractC1981ds.s(c1929cj);
        return new C1778Tf(sVarA, context, wp, view, (InterfaceC2529qe) uVar.d, interfaceC2316lg, c1929cj, (C2490pi) this.c.zzb(), BC.a((C2153ho) this.k), (Executor) this.d.zzb());
    }

    public Dl b() {
        C1765Re c1765Re = (C1765Re) ((DC) this.e).a;
        Context contextA = ((C1741Ne) this.f).a();
        VersionInfoParcel versionInfoParcelB = ((C1741Ne) this.g).b();
        C2023eq c2023eqA = ((Tg) this.h).a();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Dl(c1765Re, contextA, versionInfoParcelB, c2023eqA, c2227jd, (String) ((CC) this.i).zzb(), (Tq) this.b.zzb(), (Ek) this.c.zzb(), new L9(15), (ScheduledExecutorService) this.d.zzb(), (C2584rr) ((BC) this.j).zzb(), new Ih(((Wg) this.k).b.zzb()));
    }

    public C2064fn c() {
        C1765Re c1765Re = (C1765Re) ((DC) this.e).a;
        Sg sgA = ((Tg) this.f).b.a();
        C2924zn c2924zn = (C2924zn) this.g;
        C1841ai c1841ai = (C1841ai) this.h;
        Gi gi = (Gi) this.i;
        return new C2064fn(c1765Re, sgA, c2924zn.b, c1841ai.b, gi.b, (Gh) ((C2230jg) this.j).b.b, (FrameLayout) ((Os) ((C1969df) this.k).b).b, (Rh) this.b.zzb(), (C2195in) this.c.zzb(), (C2923zm) this.d.zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return a();
            case 1:
                Dl dlB = ((C1784Uf) this.e).b();
                C2023eq c2023eqA = ((Tg) this.f).a();
                Lq lq = (Lq) this.b.zzb();
                C1691Fc c1691Fc = (C1691Fc) this.g;
                C2272kf c2272kf = new C2272kf(((EC) c1691Fc.b).zzb(), ((EC) c1691Fc.c).zzb());
                C2280kn c2280knB = ((com.google.android.gms.ads.nonagon.signalgeneration.j) this.h).b();
                Th th = (Th) this.c.zzb();
                C1691Fc c1691Fc2 = (C1691Fc) this.i;
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                C2326lq c2326lq = new C2326lq(16, c2227jd, ((C1735Me) c1691Fc2.b).a(), BC.a((com.google.android.gms.ads.nonagon.signalgeneration.t) c1691Fc2.c), false);
                androidx.camera.core.processing.e eVarA = ((com.google.android.gms.ads.nonagon.signalgeneration.j) this.j).a();
                AbstractC1981ds.s(c2227jd);
                C1691Fc c1691Fc3 = (C1691Fc) this.k;
                Map map = ((GC) c1691Fc3.b).a;
                AbstractC1981ds.s(c2227jd);
                return new C2831xg(dlB, c2023eqA, lq, c2272kf, c2280knB, th, c2326lq, eVarA, c2227jd, new Ll(map, c2227jd, new Ih(((Wg) c1691Fc3.c).b.zzb())), (C2923zm) this.d.zzb());
            case 2:
                C2326lq c2326lq2 = ((C2834xj) this.e).b;
                C2326lq c2326lq3 = ((C2834xj) this.f).b;
                C2326lq c2326lq4 = ((C2834xj) this.g).b;
                return new C2791wj((C1683Ea) c2326lq2.d, (C1689Fa) c2326lq3.c, (InterfaceC1707Ia) c2326lq4.b, (C2146hh) this.b.zzb(), (Vg) this.c.zzb(), (C2404ni) this.d.zzb(), (Context) ((BC) this.h).zzb(), ((C2702ug) this.i).a(), ((C1741Ne) this.j).b(), ((Tg) this.k).a());
            case 3:
                return new C1930ck((Vg) this.b.zzb(), (C2489ph) this.c.zzb(), (C2746vh) this.d.zzb(), (C2875yh) ((BC) this.e).zzb(), (Qh) ((BC) this.f).zzb(), (C2404ni) ((BC) this.g).zzb(), (Hk) ((BC) this.h).zzb(), (C2584rr) ((BC) this.i).zzb(), (C2107gm) ((BC) this.j).zzb(), (C2830xf) ((BC) this.k).zzb());
            case 4:
                Context context = (Context) this.b.zzb();
                P4 p4 = (P4) this.c.zzb();
                J7 j7 = (J7) this.d.zzb();
                VersionInfoParcel versionInfoParcelB = ((C1741Ne) this.e).b();
                Object obj = ((C1969df) this.f).b;
                return new C2406nk(context, p4, j7, versionInfoParcelB, C1969df.b(), (C2429o6) ((BC) this.g).zzb(), (Gh) ((CC) this.h).zzb(), (BinderC2408nm) ((BC) this.i).zzb(), (C2067fq) ((BC) this.j).zzb(), (Hk) ((BC) this.k).zzb());
            case 5:
                return b();
            default:
                return c();
        }
    }

    public C1784Uf(C1784Uf c1784Uf, Tg tg, BC bc, C1691Fc c1691Fc, com.google.android.gms.ads.nonagon.signalgeneration.j jVar, BC bc2, C1691Fc c1691Fc2, com.google.android.gms.ads.nonagon.signalgeneration.j jVar2, C1691Fc c1691Fc3, BC bc3) {
        this.a = 1;
        this.e = c1784Uf;
        this.f = tg;
        this.b = bc;
        this.g = c1691Fc;
        this.h = jVar;
        this.c = bc2;
        this.i = c1691Fc2;
        this.j = jVar2;
        this.k = c1691Fc3;
        this.d = bc3;
    }

    public C1784Uf(C2834xj c2834xj, C2834xj c2834xj2, C2834xj c2834xj3, BC bc, BC bc2, BC bc3, BC bc4, C2702ug c2702ug, C1741Ne c1741Ne, Tg tg) {
        this.a = 2;
        this.e = c2834xj;
        this.f = c2834xj2;
        this.g = c2834xj3;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.h = bc4;
        this.i = c2702ug;
        this.j = c1741Ne;
        this.k = tg;
    }

    public /* synthetic */ C1784Uf(BC bc, BC bc2, BC bc3, HC hc, HC hc2, BC bc4, HC hc3, BC bc5, BC bc6, BC bc7, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.e = hc;
        this.f = hc2;
        this.g = bc4;
        this.h = hc3;
        this.i = bc5;
        this.j = bc6;
        this.k = bc7;
    }

    public C1784Uf(DC dc, C1741Ne c1741Ne, C1741Ne c1741Ne2, Tg tg, CC cc, BC bc, BC bc2, BC bc3, BC bc4, Wg wg) {
        this.a = 5;
        this.e = dc;
        this.f = c1741Ne;
        this.g = c1741Ne2;
        this.h = tg;
        this.i = cc;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.j = bc4;
        this.k = wg;
    }

    public C1784Uf(DC dc, Tg tg, C2924zn c2924zn, C1841ai c1841ai, Gi gi, C2230jg c2230jg, C1969df c1969df, BC bc, BC bc2, BC bc3) {
        this.a = 6;
        this.e = dc;
        this.f = tg;
        this.g = c2924zn;
        this.h = c1841ai;
        this.i = gi;
        this.j = c2230jg;
        this.k = c1969df;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
    }
}
