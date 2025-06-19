package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Hj implements CC {
    public final BC a;
    public final HC b;
    public final BC c;
    public final C1741Ne d;
    public final C1969df e;
    public final BC f;
    public final Tg g;
    public final BC h;
    public final BC i;
    public final BC j;
    public final BC k;
    public final BC l;
    public final BC m;
    public final BC n;
    public final BC o;
    public final BC p;
    public final BC q;

    public Hj(BC bc, HC hc, BC bc2, C1741Ne c1741Ne, C1969df c1969df, BC bc3, Tg tg, BC bc4, BC bc5, BC bc6, BC bc7, BC bc8, BC bc9, BC bc10, BC bc11, BC bc12, BC bc13) {
        this.a = bc;
        this.b = hc;
        this.c = bc2;
        this.d = c1741Ne;
        this.e = c1969df;
        this.f = bc3;
        this.g = tg;
        this.h = bc4;
        this.i = bc5;
        this.j = bc6;
        this.k = bc7;
        this.l = bc8;
        this.m = bc9;
        this.n = bc10;
        this.o = bc11;
        this.p = bc12;
        this.q = bc13;
    }

    @Override // com.google.android.gms.internal.ads.HC
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final Gj zzb() {
        Context context = (Context) this.a.zzb();
        C2920zj c2920zj = (C2920zj) this.b.zzb();
        P4 p4 = (P4) this.c.zzb();
        VersionInfoParcel versionInfoParcelB = this.d.b();
        Object obj = this.e.b;
        androidx.work.impl.model.c cVarB = C1969df.b();
        C2429o6 c2429o6 = (C2429o6) this.f.zzb();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        C2023eq c2023eqA = this.g.a();
        Oj oj = (Oj) this.h.zzb();
        C2406nk c2406nk = (C2406nk) this.i.zzb();
        ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.j.zzb();
        Hk hk = (Hk) this.k.zzb();
        C2584rr c2584rr = (C2584rr) this.l.zzb();
        C2107gm c2107gm = (C2107gm) this.m.zzb();
        C1974dk c1974dk = (C1974dk) this.n.zzb();
        BinderC2408nm binderC2408nm = (BinderC2408nm) this.o.zzb();
        C2067fq c2067fq = (C2067fq) this.p.zzb();
        Ek ek = (Ek) this.q.zzb();
        Gj gj = new Gj();
        gj.a = context;
        gj.b = c2920zj;
        gj.c = p4;
        gj.d = versionInfoParcelB;
        gj.e = cVarB;
        gj.f = c2429o6;
        gj.g = c2227jd;
        gj.h = c2023eqA.i;
        gj.i = oj;
        gj.j = c2406nk;
        gj.k = scheduledExecutorService;
        gj.m = hk;
        gj.n = c2584rr;
        gj.o = c2107gm;
        gj.l = c1974dk;
        gj.p = binderC2408nm;
        gj.q = c2067fq;
        gj.r = ek;
        return gj;
    }
}
