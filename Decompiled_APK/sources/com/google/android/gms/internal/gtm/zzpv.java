package com.google.android.gms.internal.gtm;

import android.content.Context;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class zzpv {
    private final ScheduledExecutorService zza;
    private ScheduledFuture zzb;

    public zzpv() {
        ScheduledExecutorService scheduledExecutorServiceZzb = zzfx.zza().zzb(1, 2);
        this.zzb = null;
        this.zza = scheduledExecutorServiceZzb;
    }

    public final void zza(Context context, zzpj zzpjVar, long j, zzpa zzpaVar) {
        synchronized (this) {
            try {
                ScheduledFuture scheduledFuture = this.zzb;
                if (scheduledFuture != null) {
                    scheduledFuture.cancel(false);
                }
                this.zzb = this.zza.schedule(new zzpu(context, zzpjVar, zzpaVar), 0L, TimeUnit.MILLISECONDS);
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
