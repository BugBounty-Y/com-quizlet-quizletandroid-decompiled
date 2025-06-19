package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Lo implements CC {
    public final /* synthetic */ int a;
    public final CC b;
    public final HC c;
    public final HC d;

    public Lo(C1741Ne c1741Ne, C1741Ne c1741Ne2, C1735Me c1735Me) {
        this.a = 1;
        this.b = c1741Ne;
        this.c = c1741Ne2;
        this.d = c1735Me;
    }

    public Wn a() {
        Context contextA = ((C1741Ne) this.b).a();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn(contextA, c2227jd, ((Tg) this.d).a(), ((C1741Ne) this.c).b());
    }

    public Wn b() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn(c2227jd, (Object) ((C1741Ne) this.b).a(), (Object) ((C1741Ne) this.c).b(), (Object) ((C1735Me) this.d).c(), 7);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return a();
            case 1:
                return b();
            default:
                AbstractC1981ds.s(((zzbvl) ((C2239jp) this.b).b.c).d);
                C2010ed c2010ed = (C2010ed) ((BC) this.d).zzb();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) ((BC) this.c).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2021eo(c2010ed, scheduledExecutorService, c2227jd);
        }
    }

    public /* synthetic */ Lo(CC cc, HC hc, HC hc2, int i) {
        this.a = i;
        this.b = cc;
        this.d = hc;
        this.c = hc2;
    }
}
