package com.google.android.gms.internal.gtm;

import android.os.RemoteException;

/* loaded from: classes2.dex */
final class zziy implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ String zzb;
    final /* synthetic */ String zzc;
    final /* synthetic */ zzhd zzd;
    final /* synthetic */ zzjb zze;

    public zziy(zzjb zzjbVar, String str, String str2, String str3, zzhd zzhdVar) {
        this.zza = str;
        this.zzb = str2;
        this.zzc = str3;
        this.zzd = zzhdVar;
        this.zze = zzjbVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean z;
        try {
            z = true;
            if (!this.zze.zza.containsKey(this.zza)) {
                this.zze.zza.put(this.zza, this.zze.zzc.zza(this.zza, this.zzb, this.zzc));
            }
        } catch (Exception e) {
            zzgp.zzb("Fail to load container: ", e, this.zze.zze);
            z = false;
        }
        try {
            zzhd zzhdVar = this.zzd;
            if (zzhdVar != null) {
                zzhdVar.zze(z, this.zza);
            }
        } catch (RemoteException e2) {
            zzgp.zzb("Error relaying callback: ", e2, this.zze.zze);
        }
    }
}
