package com.google.android.gms.internal.ads;

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Ck implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;
    public final BC d;

    public /* synthetic */ Ck(BC bc, BC bc2, BC bc3, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
    }

    public Wn a() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn(c2227jd, this.b.zzb(), this.c.zzb(), this.d.zzb(), 2);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Bk((Ek) this.b.zzb(), (Kk) this.c.zzb(), ((Integer) this.d.zzb()).intValue());
            case 1:
                return new C2326lq(21, (C2283kq) this.b.zzb(), (C2620sk) this.c.zzb(), (Hk) this.d.zzb(), false);
            case 2:
                return a();
            case 3:
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                C2839xo c2839xo = new C2839xo(c2227jd, 2);
                C2796wo c2796wo = (C2796wo) this.b.zzb();
                List list = (List) this.c.zzb();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.d.zzb();
                if (list.contains("24")) {
                    return new Io(c2796wo, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hc)).intValue(), scheduledExecutorService);
                }
                return new Io(c2839xo, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hc)).intValue(), scheduledExecutorService);
            default:
                return new Tp((Qp) this.b.zzb(), (Np) this.c.zzb(), (C1893bq) this.d.zzb());
        }
    }
}
