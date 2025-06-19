package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzby implements Runnable {
    final /* synthetic */ zzca zza;
    final /* synthetic */ zzel zzb;

    public zzby(zzca zzcaVar, zzel zzelVar) {
        this.zzb = zzelVar;
        this.zza = zzcaVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zza.zza.zzg()) {
            return;
        }
        this.zza.zza.zzE("Connected to service after a timeout");
        zzca zzcaVar = this.zza;
        zzcb.zzi(zzcaVar.zza, this.zzb);
    }
}
