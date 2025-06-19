package com.google.android.gms.internal.gtm;

import android.os.RemoteException;

/* loaded from: classes2.dex */
final class zzgi implements Runnable {
    final /* synthetic */ zzgm zza;
    private final zzgt zzb;

    public zzgi(zzgm zzgmVar, zzgt zzgtVar) {
        this.zza = zzgmVar;
        this.zzb = zzgtVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zza.zzm == 2) {
            zzhi.zzd("Evaluating tags for event ".concat(String.valueOf(this.zzb.zzb())));
            this.zza.zzl.zzf(this.zzb);
            return;
        }
        if (this.zza.zzm == 1) {
            this.zza.zzn.add(this.zzb);
            zzhi.zzd("Added event " + this.zzb.zzb() + " to pending queue.");
            return;
        }
        if (this.zza.zzm == 3) {
            zzhi.zzd("Failed to evaluate tags for event " + this.zzb.zzb() + " (container failed to load)");
            zzgt zzgtVar = this.zzb;
            if (!zzgtVar.zzf()) {
                zzhi.zzd("Discarded non-passthrough event ".concat(String.valueOf(zzgtVar.zzb())));
                return;
            }
            try {
                this.zza.zzi.zzc("app", zzgtVar.zzb(), zzgtVar.zza(), zzgtVar.currentTimeMillis());
                zzhi.zzd("Logged passthrough event " + this.zzb.zzb() + " to Firebase.");
            } catch (RemoteException e) {
                zzgp.zzb("Error logging event with measurement proxy:", e, this.zza.zza);
            }
        }
    }
}
