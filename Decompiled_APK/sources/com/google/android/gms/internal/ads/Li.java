package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Li implements CC {
    public final BC a;
    public final Gi b;
    public final Mi c;
    public final Mi d;
    public final C1969df e;
    public final BC f;
    public final BC g;
    public final BC h;
    public final BC i;
    public final C2702ug j;
    public final C1741Ne k;
    public final Tg l;
    public final BC m;
    public final BC n;
    public final BC o;
    public final BC p;
    public final BC q;
    public final BC r;
    public final BC s;
    public final BC t;
    public final BC u;
    public final BC v;
    public final BC w;
    public final BC x;

    public Li(BC bc, Gi gi, Mi mi, Mi mi2, C1969df c1969df, BC bc2, BC bc3, BC bc4, BC bc5, C2702ug c2702ug, C1741Ne c1741Ne, Tg tg, BC bc6, BC bc7, BC bc8, BC bc9, BC bc10, BC bc11, BC bc12, BC bc13, BC bc14, BC bc15, BC bc16, BC bc17) {
        this.a = bc;
        this.b = gi;
        this.c = mi;
        this.d = mi2;
        this.e = c1969df;
        this.f = bc2;
        this.g = bc3;
        this.h = bc4;
        this.i = bc5;
        this.j = c2702ug;
        this.k = c1741Ne;
        this.l = tg;
        this.m = bc6;
        this.n = bc7;
        this.o = bc8;
        this.p = bc9;
        this.q = bc10;
        this.r = bc11;
        this.s = bc12;
        this.t = bc13;
        this.u = bc14;
        this.v = bc15;
        this.w = bc16;
        this.x = bc17;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Context context = (Context) this.a.zzb();
        C1929cj c1929cj = (C1929cj) this.b.b.b;
        AbstractC1981ds.s(c1929cj);
        JSONObject jSONObject = (JSONObject) this.c.b.a;
        AbstractC1981ds.s(jSONObject);
        C1843ak c1843ak = (C1843ak) this.d.b.b;
        AbstractC1981ds.s(c1843ak);
        Yi yiA = this.e.a();
        P4 p4 = (P4) this.f.zzb();
        C2146hh c2146hh = (C2146hh) this.g.zzb();
        Vg vg = (Vg) this.h.zzb();
        C2404ni c2404ni = (C2404ni) this.i.zzb();
        Vp vpA = this.j.a();
        VersionInfoParcel versionInfoParcelB = this.k.b();
        C2023eq c2023eqA = this.l.a();
        C1724Kf c1724Kf = (C1724Kf) this.m.zzb();
        ViewOnClickListenerC2362mj viewOnClickListenerC2362mj = (ViewOnClickListenerC2362mj) this.n.zzb();
        com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) this.o.zzb();
        C2361mi c2361mi = (C2361mi) this.p.zzb();
        C2584rr c2584rr = (C2584rr) this.q.zzb();
        Tq tq = (Tq) this.r.zzb();
        BinderC2408nm binderC2408nm = (BinderC2408nm) this.s.zzb();
        C2535qk c2535qk = (C2535qk) this.t.zzb();
        C2276kj c2276kj = (C2276kj) this.u.zzb();
        Ah ah = (Ah) this.v.zzb();
        com.google.android.gms.ads.internal.a aVar2 = (com.google.android.gms.ads.internal.a) this.w.zzb();
        return new Ki(context, c1929cj, jSONObject, c1843ak, yiA, p4, c2146hh, vg, c2404ni, vpA, versionInfoParcelB, c2023eqA, c1724Kf, viewOnClickListenerC2362mj, aVar, c2361mi, c2584rr, tq, binderC2408nm, c2535qk, c2276kj, ah, aVar2);
    }
}
