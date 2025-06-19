package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;

/* loaded from: classes2.dex */
final class zzfb {
    private final a zza;
    private long zzb;

    public zzfb(a aVar) {
        u.h(aVar);
        this.zza = aVar;
    }

    public final void zza() {
        this.zzb = 0L;
    }

    public final void zzb() {
        this.zzb = this.zza.elapsedRealtime();
    }

    public final boolean zzc(long j) {
        return this.zzb == 0 || this.zza.elapsedRealtime() - this.zzb > j;
    }

    public zzfb(a aVar, long j) {
        u.h(aVar);
        this.zza = aVar;
        this.zzb = j;
    }
}
