package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.jj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2233jj implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;
    public final HC d;
    public final HC e;
    public final HC f;
    public final HC g;
    public final HC h;
    public final HC i;

    public C2233jj(C1729Le c1729Le, Tg tg, HC hc, C1969df c1969df, CC cc, CC cc2, BC bc, BC bc2) {
        this.a = 0;
        this.d = c1729Le;
        this.e = tg;
        this.f = hc;
        this.g = c1969df;
        this.h = cc;
        this.i = cc2;
        this.b = bc;
        this.c = bc2;
    }

    public C2191ij a() {
        com.google.android.gms.ads.internal.util.C cA = ((C1729Le) this.d).a();
        C2023eq c2023eqA = ((Tg) this.e).a();
        C1842aj c1842aj = (C1842aj) this.f.zzb();
        Yi yiA = ((C1969df) this.g).a();
        C2534qj c2534qj = (C2534qj) ((CC) this.h).zzb();
        C2662tj c2662tj = (C2662tj) ((CC) this.i).zzb();
        Executor executor = (Executor) this.b.zzb();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new C2191ij(cA, c2023eqA, c1842aj, yiA, c2534qj, c2662tj, executor, c2227jd, (Wi) this.c.zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return a();
            case 1:
                return new Yj((Vg) this.b.zzb(), (C2489ph) this.c.zzb(), (C2746vh) ((BC) this.d).zzb(), (C2875yh) ((BC) this.e).zzb(), (Qh) ((BC) this.f).zzb(), ((C2702ug) this.g).a(), ((C2702ug) this.h).b.l(), (C2830xf) ((BC) this.i).zzb());
            case 2:
                return new C2493pl((C2536ql) this.b.zzb(), (C2750vl) this.c.zzb(), (C2062fl) ((BC) this.d).zzb(), ((C1741Ne) this.e).a(), ((C1741Ne) this.f).b(), (C2278kl) ((BC) this.g).zzb(), (BinderC2707ul) ((BC) this.h).zzb(), new SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc(), new SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc(), ((C1735Me) this.i).c());
            default:
                return new Sp((String) ((DC) this.d).a, (Qp) this.b.zzb(), (Context) ((DC) this.e).a, (Np) this.c.zzb(), (C1893bq) ((BC) this.f).zzb(), ((C1741Ne) this.g).b(), (P4) ((BC) this.h).zzb(), (Hk) ((BC) this.i).zzb());
        }
    }

    public /* synthetic */ C2233jj(BC bc, BC bc2, BC bc3, HC hc, HC hc2, HC hc3, HC hc4, HC hc5, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.e = hc;
        this.f = hc2;
        this.g = hc3;
        this.h = hc4;
        this.i = hc5;
    }

    public C2233jj(DC dc, BC bc, DC dc2, BC bc2, BC bc3, C1741Ne c1741Ne, BC bc4, BC bc5) {
        this.a = 3;
        this.d = dc;
        this.b = bc;
        this.e = dc2;
        this.c = bc2;
        this.f = bc3;
        this.g = c1741Ne;
        this.h = bc4;
        this.i = bc5;
    }
}
