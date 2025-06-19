package com.google.android.gms.internal.gtm;

import java.util.Map;

/* loaded from: classes2.dex */
final class zzgy implements Runnable {
    final /* synthetic */ zzgx zza;
    final /* synthetic */ long zzb;
    final /* synthetic */ String zzc;
    final /* synthetic */ String zzd;
    final /* synthetic */ String zze;
    final /* synthetic */ Map zzf;
    final /* synthetic */ String zzg;
    final /* synthetic */ zzgz zzh;

    public zzgy(zzgz zzgzVar, zzgx zzgxVar, long j, String str, String str2, String str3, Map map, String str4) {
        this.zza = zzgxVar;
        this.zzb = j;
        this.zzc = str;
        this.zzd = str2;
        this.zze = str3;
        this.zzf = map;
        this.zzg = str4;
        this.zzh = zzgzVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zzh.zze == null) {
            zzgz zzgzVar = this.zzh;
            zzgx zzgxVar = this.zza;
            zzig zzigVarZzf = zzig.zzf();
            zzigVarZzf.zzj(zzgzVar.zzf, zzgxVar);
            this.zzh.zze = zzigVarZzf.zze();
        }
        zzgz zzgzVar2 = this.zzh;
        zzgzVar2.zze.zzb(this.zzb, this.zzc, this.zzd, this.zze, this.zzf, this.zzg);
    }
}
