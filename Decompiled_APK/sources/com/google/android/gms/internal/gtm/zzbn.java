package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzbn implements Runnable {
    final /* synthetic */ zzcy zza;
    final /* synthetic */ zzbp zzb;

    public zzbn(zzbp zzbpVar, zzcy zzcyVar) {
        this.zza = zzcyVar;
        this.zzb = zzbpVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zzb.zza.zzf(this.zza);
    }
}
