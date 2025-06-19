package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class K7 implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;
    public final BC c;
    public final BC d;

    public /* synthetic */ K7(C1741Ne c1741Ne, BC bc, BC bc2, int i) {
        this.a = i;
        this.b = c1741Ne;
        this.c = bc;
        this.d = bc2;
    }

    public C2021eo a() {
        return new C2021eo((ApplicationInfo) this.c.zzb(), (PackageInfo) this.d.zzb(), this.b.a(), 2);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                this.b.a();
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.c.zzb();
                return new J7(scheduledExecutorService);
            case 1:
                Context contextA = this.b.a();
                C2010ed c2010ed = (C2010ed) this.c.zzb();
                ScheduledExecutorService scheduledExecutorService2 = (ScheduledExecutorService) this.d.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2410no(contextA, c2010ed, scheduledExecutorService2, c2227jd);
            default:
                return a();
        }
    }

    public K7(BC bc, BC bc2, C1741Ne c1741Ne) {
        this.a = 2;
        this.c = bc;
        this.d = bc2;
        this.b = c1741Ne;
    }
}
