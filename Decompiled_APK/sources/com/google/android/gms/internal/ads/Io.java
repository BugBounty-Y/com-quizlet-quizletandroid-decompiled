package com.google.android.gms.internal.ads;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class Io implements Vo {
    public final Vo a;
    public final long b;
    public final ScheduledExecutorService c;

    public Io(Vo vo, long j, ScheduledExecutorService scheduledExecutorService) {
        this.a = vo;
        this.b = j;
        this.c = scheduledExecutorService;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return this.a.zza();
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        com.google.common.util.concurrent.e eVarZzb = this.a.zzb();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r2)).booleanValue()) {
            timeUnit = TimeUnit.MICROSECONDS;
        }
        long j = this.b;
        if (j > 0) {
            eVarZzb = AbstractC2025es.O(eVarZzb, j, timeUnit, this.c);
        }
        return AbstractC2025es.A(eVarZzb, Throwable.class, new D9(this, 9), AbstractC2270kd.g);
    }
}
