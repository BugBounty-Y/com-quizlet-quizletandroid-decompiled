package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zziu implements Runnable {
    final /* synthetic */ boolean zza;
    final /* synthetic */ String zzb;
    final /* synthetic */ zziv zzc;

    public zziu(zziv zzivVar, boolean z, String str) {
        this.zza = z;
        this.zzb = str;
        this.zzc = zzivVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzix zzixVar = this.zzc.zza;
        if (zzixVar.zzm != 2) {
            zzhi.zze("Container load callback completed after timeout");
            return;
        }
        if (this.zza) {
            zzixVar.zzm = 3;
            zzhi.zzd("Container " + this.zzb + " loaded.");
        } else {
            zzixVar.zzm = 4;
            zzhi.zza("Error loading container:".concat(String.valueOf(this.zzb)));
        }
        while (!this.zzc.zza.zzn.isEmpty()) {
            zzix zzixVar2 = this.zzc.zza;
            zzixVar2.zzf.execute((Runnable) zzixVar2.zzn.remove());
        }
    }
}
