package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.util.a;

/* loaded from: classes2.dex */
public final class zzem {
    private long zzb;
    private final a zze;
    private final Object zzc = new Object();
    private double zza = 60.0d;
    private final String zzd = "tracking";

    public zzem(int i, long j, String str, a aVar) {
        this.zze = aVar;
    }

    public final boolean zza() {
        synchronized (this.zzc) {
            try {
                long jCurrentTimeMillis = this.zze.currentTimeMillis();
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
                zzen.zze("Excessive " + this.zzd + " detected; call ignored.");
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
