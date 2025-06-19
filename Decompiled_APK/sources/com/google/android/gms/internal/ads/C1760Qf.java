package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.Qf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1760Qf implements CC {
    public final /* synthetic */ int a;
    public final HC b;
    public final HC c;
    public final HC d;
    public final HC e;

    public C1760Qf(C1741Ne c1741Ne, BC bc, HC hc, BC bc2) {
        this.a = 9;
        this.e = c1741Ne;
        this.b = bc;
        this.d = hc;
        this.c = bc2;
    }

    public C2752vn a() {
        return new C2752vn((Lq) ((BC) this.b).zzb(), (Xv) ((BC) this.c).zzb(), (InterfaceC2837xm) this.e.zzb(), (Am) ((CC) this.d).zzb(), 0);
    }

    public Xo b() {
        Context contextA = ((C1741Ne) this.e).a();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Xo(contextA, c2227jd, ((IC) this.d).zzb(), (Tq) ((BC) this.b).zzb(), (Hk) ((BC) this.c).zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Lq lq = (Lq) ((BC) this.b).zzb();
                Xv xv = (Xv) ((BC) this.c).zzb();
                C1715Jc c1715Jc = (C1715Jc) this.e;
                return new C2752vn(lq, xv, ((C1730Lf) this.d).b(), new Im(0, (Context) c1715Jc.b.zzb(), (C1777Te) c1715Jc.c.a), 0);
            case 1:
                Lq lq2 = (Lq) ((BC) this.b).zzb();
                Xv xv2 = (Xv) ((BC) this.c).zzb();
                C1715Jc c1715Jc2 = (C1715Jc) this.e;
                return new C2752vn(lq2, xv2, ((C1730Lf) this.d).b(), new Om((Context) c1715Jc2.b.zzb(), (C1789Ve) c1715Jc2.c.a), 0);
            case 2:
                return new C2145hg(((C2702ug) this.e).a(), (C2146hh) ((BC) this.b).zzb(), (C2789wh) ((BC) this.c).zzb(), (Ch) ((BC) this.d).zzb());
            case 3:
                return new Cg((com.google.android.gms.common.util.a) ((BC) this.b).zzb(), (Dg) ((BC) this.c).zzb(), ((Tg) this.e).a(), (String) ((BC) this.d).zzb());
            case 4:
                Lq lq3 = (Lq) ((BC) this.b).zzb();
                Xv xv3 = (Xv) ((BC) this.c).zzb();
                C1715Jc c1715Jc3 = (C1715Jc) this.e;
                return new C2752vn(lq3, xv3, ((C1730Lf) this.d).b(), new Im(1, (Context) c1715Jc3.b.zzb(), (C1813Ze) c1715Jc3.c.a), 0);
            case 5:
                C2406nk c2406nk = (C2406nk) ((BC) this.b).zzb();
                C1843ak c1843ak = (C1843ak) ((Mi) this.e).b.b;
                AbstractC1981ds.s(c1843ak);
                C1736Mf c1736Mf = (C1736Mf) ((BC) this.c).zzb();
                Ki ki = (Ki) ((C2833xi) this.d).b.zzb();
                AbstractC1981ds.s(ki);
                return new C2534qj(c2406nk, c1843ak, c1736Mf, ki);
            case 6:
                return new Uj(((C1741Ne) this.b).a(), ((C1969df) this.c).a(), ((C2233jj) this.e).a(), (Ui) ((C2153ho) this.d).zzb());
            case 7:
                return new Vj((String) ((C2702ug) this.c).b.d, (Ui) ((C2153ho) this.e).zzb(), ((C1969df) this.d).a(), (Hk) ((BC) this.b).zzb());
            case 8:
                Lq lq4 = (Lq) ((BC) this.b).zzb();
                Xv xv4 = (Xv) ((BC) this.c).zzb();
                C1715Jc c1715Jc4 = (C1715Jc) this.e;
                return new C2752vn(lq4, xv4, ((C1730Lf) this.d).b(), new Im(2, (Context) c1715Jc4.b.zzb(), (C1882bf) c1715Jc4.c.a), 0);
            case 9:
                return new BinderC2408nm(((C1741Ne) this.e).a(), (C2107gm) ((BC) this.b).zzb(), (com.google.android.gms.ads.internal.util.client.k) this.d.zzb(), (Hk) ((BC) this.c).zzb());
            case 10:
                return a();
            case 11:
                return new C2752vn((Lq) ((BC) this.b).zzb(), (Xv) ((BC) this.c).zzb(), (D7) ((C2924zn) this.e).b.b, new C2881yn((C1813Ze) ((C1753Pe) this.d).b.a, 24), 1);
            case 12:
                Yn ynA = ((Ok) this.e).a();
                C2796wo c2796wo = (C2796wo) ((BC) this.b).zzb();
                List list = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list.contains("10")) {
                    return new Io(c2796wo, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.fc)).intValue(), scheduledExecutorService);
                }
                return new Io(ynA, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.fc)).intValue(), scheduledExecutorService);
            case 13:
                Yn ynA2 = ((Ni) this.e).a();
                C2796wo c2796wo2 = (C2796wo) ((BC) this.b).zzb();
                List list2 = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService2 = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list2.contains("54")) {
                    return new Io(c2796wo2, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.oc)).intValue(), scheduledExecutorService2);
                }
                return new Io(ynA2, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.oc)).intValue(), scheduledExecutorService2);
            case 14:
                C2281ko c2281koB = ((C1735Me) this.e).b();
                C2796wo c2796wo3 = (C2796wo) ((BC) this.b).zzb();
                List list3 = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService3 = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list3.contains("13")) {
                    return new Io(c2796wo3, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.nc)).intValue(), scheduledExecutorService3);
                }
                return new Io(c2281koB, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.nc)).intValue(), scheduledExecutorService3);
            case 15:
                Yn ynA3 = ((C1747Oe) this.e).a();
                C2796wo c2796wo4 = (C2796wo) ((BC) this.b).zzb();
                List list4 = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService4 = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list4.contains("60")) {
                    return new Io(c2796wo4, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Mc)).intValue(), scheduledExecutorService4);
                }
                return new Io(ynA3, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Mc)).intValue(), scheduledExecutorService4);
            case 16:
                Wn wnB = ((Lo) this.e).b();
                C2796wo c2796wo5 = (C2796wo) ((BC) this.b).zzb();
                List list5 = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService5 = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list5.contains("35")) {
                    return new Io(c2796wo5, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.cc)).intValue(), scheduledExecutorService5);
                }
                return new Io(wnB, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.cc)).intValue(), scheduledExecutorService5);
            case 17:
                C2281ko c2281koD = ((C1735Me) this.e).d();
                C2796wo c2796wo6 = (C2796wo) ((BC) this.b).zzb();
                List list6 = (List) ((BC) this.c).zzb();
                ScheduledExecutorService scheduledExecutorService6 = (ScheduledExecutorService) ((BC) this.d).zzb();
                if (list6.contains("39")) {
                    return new Io(c2796wo6, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Zb)).intValue(), scheduledExecutorService6);
                }
                return new Io(c2281koD, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Zb)).intValue(), scheduledExecutorService6);
            case 18:
                return b();
            case 19:
                Er er = (Er) ((BC) this.b).zzb();
                C1747Oe c1747Oe = (C1747Oe) this.e;
                return new C2928zr(er, new Fi(c1747Oe.b.a(), (Hk) c1747Oe.c.zzb()), ((C1741Ne) this.d).a(), (com.google.android.gms.common.util.a) ((BC) this.c).zzb());
            default:
                return new Er(((C1741Ne) this.e).a(), ((C1741Ne) this.d).b(), (ScheduledExecutorService) ((BC) this.b).zzb(), (com.google.android.gms.common.util.a) ((BC) this.c).zzb());
        }
    }

    public /* synthetic */ C1760Qf(C1741Ne c1741Ne, CC cc, BC bc, BC bc2, int i) {
        this.a = i;
        this.e = c1741Ne;
        this.d = cc;
        this.b = bc;
        this.c = bc2;
    }

    public C1760Qf(C2702ug c2702ug, C2153ho c2153ho, C1969df c1969df, BC bc) {
        this.a = 7;
        this.c = c2702ug;
        this.e = c2153ho;
        this.d = c1969df;
        this.b = bc;
    }

    public C1760Qf(BC bc, C1747Oe c1747Oe, C1741Ne c1741Ne, BC bc2) {
        this.a = 19;
        this.b = bc;
        this.e = c1747Oe;
        this.d = c1741Ne;
        this.c = bc2;
    }

    public C1760Qf(BC bc, Mi mi, BC bc2, C2833xi c2833xi) {
        this.a = 5;
        this.b = bc;
        this.e = mi;
        this.c = bc2;
        this.d = c2833xi;
    }

    public /* synthetic */ C1760Qf(CC cc, BC bc, BC bc2, BC bc3, int i) {
        this.a = i;
        this.e = cc;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
    }

    public /* synthetic */ C1760Qf(HC hc, HC hc2, HC hc3, HC hc4, int i) {
        this.a = i;
        this.b = hc;
        this.c = hc2;
        this.e = hc3;
        this.d = hc4;
    }
}
