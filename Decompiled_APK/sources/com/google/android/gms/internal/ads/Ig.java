package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Ig implements CC {
    public final /* synthetic */ int a = 5;
    public final CC b;
    public final BC c;
    public final BC d;
    public final HC e;
    public final CC f;
    public final HC g;
    public final HC h;

    public Ig(C1741Ne c1741Ne, Tg tg, C1741Ne c1741Ne2, C1729Le c1729Le, BC bc, BC bc2, BC bc3) {
        this.b = c1741Ne;
        this.f = tg;
        this.g = c1741Ne2;
        this.h = c1729Le;
        this.c = bc;
        this.d = bc2;
        this.e = bc3;
    }

    public Lm a() {
        return new Lm((C1789Ve) ((DC) this.b).a, (Context) this.c.zzb(), (Executor) this.d.zzb(), (C2406nk) ((BC) this.e).zzb(), ((Tg) this.f).a(), (InterfaceC2544qt) ((BC) this.g).zzb(), (Ek) ((BC) this.h).zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Hg(((C1741Ne) this.b).a(), ((Tg) this.f).a(), ((C1741Ne) this.g).b(), ((C1729Le) this.h).a(), (C1931cl) this.c.zzb(), (Uq) this.d.zzb(), (C2493pl) ((BC) this.e).zzb());
            case 1:
                Context contextA = ((C1741Ne) this.b).a();
                C2283kq c2283kq = (C2283kq) this.c.zzb();
                Hk hk = (Hk) this.d.zzb();
                C1849aq c1849aq = (C1849aq) ((C2702ug) this.f).b.b;
                AbstractC1981ds.s(c1849aq);
                return new Ak(contextA, c2283kq, hk, c1849aq, ((C2702ug) this.g).a(), (C2107gm) ((BC) this.e).zzb(), (String) ((CC) this.h).zzb());
            case 2:
                return new Ek(((C1741Ne) this.b).a(), (Kk) this.c.zzb(), ((C1729Le) this.g).b(), ((Tg) this.f).a(), (String) this.d.zzb(), (String) this.h.zzb(), (com.google.android.gms.ads.internal.e) ((BC) this.e).zzb());
            case 3:
                return a();
            case 4:
                C1759Qe c1759Qe = (C1759Qe) ((DC) this.b).a;
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new Zm(c1759Qe, c2227jd, ((C1703Hc) this.f).b(), (C2412nq) this.c.zzb(), (C1974dk) this.d.zzb(), (Ek) ((BC) this.e).zzb(), ((C1741Ne) this.g).b(), (Context) ((BC) this.h).zzb(), new L9(17));
            case 5:
                C2010ed c2010ed = (C2010ed) this.c.zzb();
                boolean z = ((zzbvl) ((C2239jp) this.b).b.c).a.getBoolean("is_gbid");
                boolean z2 = ((zzbvl) ((C2239jp) this.f).b.c).k;
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                AbstractC1981ds.s(((zzbvl) ((C2239jp) this.g).b.c).d);
                return new C2282kp(c2010ed, z, z2, c2227jd2, (ScheduledExecutorService) this.d.zzb(), ((C2239jp) this.h).a().intValue(), ((zzbvl) ((C2239jp) this.e).b.c).o);
            case 6:
                return new BinderC2625sp((C1765Re) ((DC) this.b).a, (Context) ((DC) this.f).a, (String) ((DC) this.h).a, (C2454op) this.c.zzb(), (C2411np) this.d.zzb(), ((C1741Ne) this.g).b(), (Hk) ((BC) this.e).zzb());
            default:
                return new C2668tp((Context) ((DC) this.b).a, (Executor) this.c.zzb(), (com.google.android.gms.ads.internal.client.zzr) ((DC) this.f).a, (C1765Re) ((DC) this.g).a, (Ln) this.d.zzb(), (Nn) ((BC) this.e).zzb(), new C1979dq(), (Rh) ((BC) this.h).zzb());
        }
    }

    public Ig(C1741Ne c1741Ne, BC bc, C1729Le c1729Le, Tg tg, BC bc2, HC hc, BC bc3) {
        this.b = c1741Ne;
        this.c = bc;
        this.g = c1729Le;
        this.f = tg;
        this.d = bc2;
        this.h = hc;
        this.e = bc3;
    }

    public Ig(C1741Ne c1741Ne, BC bc, BC bc2, C2702ug c2702ug, C2702ug c2702ug2, BC bc3, CC cc) {
        this.b = c1741Ne;
        this.c = bc;
        this.d = bc2;
        this.f = c2702ug;
        this.g = c2702ug2;
        this.e = bc3;
        this.h = cc;
    }

    public Ig(BC bc, C2239jp c2239jp, C2239jp c2239jp2, C2239jp c2239jp3, BC bc2, C2239jp c2239jp4, C2239jp c2239jp5) {
        this.c = bc;
        this.b = c2239jp;
        this.f = c2239jp2;
        this.g = c2239jp3;
        this.d = bc2;
        this.h = c2239jp4;
        this.e = c2239jp5;
    }

    public Ig(DC dc, C1703Hc c1703Hc, BC bc, BC bc2, BC bc3, C1741Ne c1741Ne, BC bc4) {
        this.b = dc;
        this.f = c1703Hc;
        this.c = bc;
        this.d = bc2;
        this.e = bc3;
        this.g = c1741Ne;
        this.h = bc4;
    }

    public Ig(DC dc, BC bc, BC bc2, BC bc3, Tg tg, BC bc4, BC bc5) {
        this.b = dc;
        this.c = bc;
        this.d = bc2;
        this.e = bc3;
        this.f = tg;
        this.g = bc4;
        this.h = bc5;
    }

    public Ig(DC dc, BC bc, DC dc2, DC dc3, BC bc2, BC bc3, BC bc4) {
        this.b = dc;
        this.c = bc;
        this.f = dc2;
        this.g = dc3;
        this.d = bc2;
        this.e = bc3;
        this.h = bc4;
    }

    public Ig(DC dc, DC dc2, DC dc3, BC bc, BC bc2, C1741Ne c1741Ne, BC bc3) {
        this.b = dc;
        this.f = dc2;
        this.h = dc3;
        this.c = bc;
        this.d = bc2;
        this.g = c1741Ne;
        this.e = bc3;
    }
}
