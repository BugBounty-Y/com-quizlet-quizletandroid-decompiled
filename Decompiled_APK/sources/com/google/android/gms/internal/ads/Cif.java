package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.if, reason: invalid class name */
/* loaded from: classes2.dex */
public final class Cif implements CC {
    public final /* synthetic */ int a = 1;
    public final C1741Ne b;
    public final BC c;
    public final BC d;
    public final BC e;
    public final BC f;
    public final BC g;
    public final BC h;
    public final BC i;
    public final BC j;
    public final CC k;
    public final HC l;
    public final HC m;
    public final CC n;
    public final CC o;

    public Cif(C1741Ne c1741Ne, C1741Ne c1741Ne2, BC bc, BC bc2, BC bc3, BC bc4, BC bc5, BC bc6, BC bc7, C1741Ne c1741Ne3, BC bc8, C1735Me c1735Me, BC bc9, BC bc10) {
        this.b = c1741Ne;
        this.k = c1741Ne2;
        this.c = bc;
        this.d = bc2;
        this.e = bc3;
        this.f = bc4;
        this.g = bc5;
        this.h = bc6;
        this.i = bc7;
        this.n = c1741Ne3;
        this.j = bc8;
        this.o = c1735Me;
        this.l = bc9;
        this.m = bc10;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new BinderC2144hf(this.b.a(), ((C1741Ne) this.k).b(), (C2663tk) this.c.zzb(), (InterfaceC2837xm) this.d.zzb(), (Cn) this.e.zzb(), (C1931cl) this.f.zzb(), (C1739Nc) this.g.zzb(), (C2749vk) this.h.zzb(), (C2493pl) this.i.zzb(), new C2302l8(((C1741Ne) this.n).b.b), (Uq) this.j.zzb(), C2326lq.s(((C1735Me) this.o).b.a()), (Eg) ((BC) this.l).zzb(), (Hk) ((BC) this.m).zzb());
            default:
                Context contextA = this.b.a();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                Executor executor = (Executor) this.c.zzb();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.d.zzb();
                C1849aq c1849aq = (C1849aq) ((C2702ug) this.k).b.b;
                AbstractC1981ds.s(c1849aq);
                Vp vpA = ((C2702ug) this.l).a();
                C2542qr c2542qr = (C2542qr) this.e.zzb();
                C2155hq c2155hq = (C2155hq) this.f.zzb();
                View view = (View) ((CC) this.m).zzb();
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.n.zzb();
                P4 p4 = (P4) this.g.zzb();
                J7 j7 = (J7) this.h.zzb();
                return new C1682Df(contextA, c2227jd, executor, scheduledExecutorService, c1849aq, vpA, c2542qr, c2155hq, view, interfaceC2529qe, p4, j7, ((Tg) this.o).b.e, (Ah) this.j.zzb());
        }
    }

    public Cif(C1741Ne c1741Ne, BC bc, BC bc2, C2702ug c2702ug, C2702ug c2702ug2, BC bc3, BC bc4, CC cc, CC cc2, BC bc5, BC bc6, BC bc7, Tg tg, BC bc8) {
        this.b = c1741Ne;
        this.c = bc;
        this.d = bc2;
        this.k = c2702ug;
        this.l = c2702ug2;
        this.e = bc3;
        this.f = bc4;
        this.m = cc;
        this.n = cc2;
        this.g = bc5;
        this.h = bc6;
        this.i = bc7;
        this.o = tg;
        this.j = bc8;
    }
}
