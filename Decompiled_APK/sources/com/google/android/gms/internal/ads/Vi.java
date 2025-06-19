package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Vi implements CC {
    public final com.google.android.gms.ads.nonagon.signalgeneration.n a;
    public final BC b;
    public final C1969df c;
    public final CC d;
    public final C2233jj e;
    public final HC f;
    public final Gi g;
    public final BC h;
    public final BC i;
    public final BC j;
    public final BC k;
    public final BC l;
    public final C1839ag m;
    public final BC n;
    public final C1741Ne o;
    public final C1741Ne p;
    public final BC q;
    public final BC r;
    public final BC s;

    public Vi(com.google.android.gms.ads.nonagon.signalgeneration.n nVar, BC bc, C1969df c1969df, CC cc, C2233jj c2233jj, HC hc, Gi gi, BC bc2, BC bc3, BC bc4, BC bc5, BC bc6, C1839ag c1839ag, BC bc7, C1741Ne c1741Ne, C1741Ne c1741Ne2, BC bc8, BC bc9, BC bc10) {
        this.a = nVar;
        this.b = bc;
        this.c = c1969df;
        this.d = cc;
        this.e = c2233jj;
        this.f = hc;
        this.g = gi;
        this.h = bc2;
        this.i = bc3;
        this.j = bc4;
        this.k = bc5;
        this.l = bc6;
        this.m = c1839ag;
        this.n = bc7;
        this.o = c1741Ne;
        this.p = c1741Ne2;
        this.q = bc8;
        this.r = bc9;
        this.s = bc10;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        com.google.android.datatransport.cct.internal.s sVarA = this.a.a();
        Executor executor = (Executor) this.b.zzb();
        Yi yiA = this.c.a();
        InterfaceC1886bj interfaceC1886bj = (InterfaceC1886bj) this.d.zzb();
        C2191ij c2191ijA = this.e.a();
        C1842aj c1842aj = (C1842aj) this.f.zzb();
        C1929cj c1929cj = (C1929cj) this.g.b.b;
        AbstractC1981ds.s(c1929cj);
        InterfaceC2907zC interfaceC2907zCA = BC.a(this.h);
        InterfaceC2907zC interfaceC2907zCA2 = BC.a(this.i);
        InterfaceC2907zC interfaceC2907zCA3 = BC.a(this.j);
        InterfaceC2907zC interfaceC2907zCA4 = BC.a(this.k);
        InterfaceC2907zC interfaceC2907zCA5 = BC.a(this.l);
        C1839ag c1839ag = this.m;
        C1727Lc c1727Lc = new C1727Lc(c1839ag.b.a(), c1839ag.c.a().f);
        P4 p4 = (P4) this.n.zzb();
        VersionInfoParcel versionInfoParcelB = this.o.b();
        Context contextA = this.p.a();
        Wi wi = (Wi) this.q.zzb();
        Mn mn = (Mn) this.r.zzb();
        return new Ui(sVarA, executor, yiA, interfaceC1886bj, c2191ijA, c1842aj, c1929cj, interfaceC2907zCA, interfaceC2907zCA2, interfaceC2907zCA3, interfaceC2907zCA4, interfaceC2907zCA5, c1727Lc, p4, versionInfoParcelB, contextA, wi, mn);
    }
}
