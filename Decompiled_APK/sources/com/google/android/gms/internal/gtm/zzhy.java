package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;

/* loaded from: classes2.dex */
final class zzhy {
    private long zzb;
    private final Object zzc = new Object();
    private double zza = 60.0d;
    private final a zzd = b.a;

    public final boolean zza() {
        synchronized (this.zzc) {
            try {
                long jCurrentTimeMillis = this.zzd.currentTimeMillis();
                double dMin = this.zza;
                if (dMin < 60.0d) {
                    double d = (jCurrentTimeMillis - this.zzb) / 2000.0d;
                    if (d > 0.0d) {
                        dMin = Math.min(60.0d, dMin + d);
                        this.zza = dMin;
                    }
                }
                this.zzb = jCurrentTimeMillis;
                if (dMin >= 1.0d) {
                    this.zza = dMin - 1.0d;
                    return true;
                }
                zzhi.zze("No more tokens available.");
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
