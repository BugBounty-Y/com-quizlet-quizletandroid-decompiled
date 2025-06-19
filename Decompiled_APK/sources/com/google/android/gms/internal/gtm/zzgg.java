package com.google.android.gms.internal.gtm;

import android.os.RemoteException;

/* loaded from: classes2.dex */
final class zzgg implements Runnable {
    final /* synthetic */ zzgm zza;

    public /* synthetic */ zzgg(zzgm zzgmVar, zzgl zzglVar) {
        this.zza = zzgmVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zza.zzm = 3;
        zzhi.zze("Container " + this.zza.zzb + " loading failed.");
        zzgm zzgmVar = this.zza;
        if (zzgmVar.zzn != null) {
            for (zzgt zzgtVar : zzgmVar.zzn) {
                if (zzgtVar.zzf()) {
                    try {
                        this.zza.zzi.zzc("app", zzgtVar.zzb(), zzgtVar.zza(), zzgtVar.currentTimeMillis());
                        zzhi.zzd("Logged event " + zzgtVar.zzb() + " to Firebase (marked as passthrough).");
                    } catch (RemoteException e) {
                        zzgp.zzb("Error logging event with measurement proxy:", e, this.zza.zza);
                    }
                } else {
                    zzhi.zzd("Discarded event " + zzgtVar.zzb() + " (marked as non-passthrough).");
                }
            }
            this.zza.zzn = null;
        }
    }
}
