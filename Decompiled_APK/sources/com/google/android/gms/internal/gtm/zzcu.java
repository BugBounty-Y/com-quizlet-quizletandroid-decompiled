package com.google.android.gms.internal.gtm;

import android.os.Looper;
import com.google.android.gms.analytics.j;

/* loaded from: classes2.dex */
final class zzcu implements Runnable {
    final /* synthetic */ zzcv zza;

    public zzcu(zzcv zzcvVar) {
        this.zza = zzcvVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            j jVarZzd = this.zza.zzb.zzd();
            jVarZzd.getClass();
            jVarZzd.b.submit(this);
        } else {
            zzcv zzcvVar = this.zza;
            boolean zZzh = zzcvVar.zzh();
            zzcvVar.zzd = 0L;
            if (zZzh) {
                this.zza.zza();
            }
        }
    }
}
