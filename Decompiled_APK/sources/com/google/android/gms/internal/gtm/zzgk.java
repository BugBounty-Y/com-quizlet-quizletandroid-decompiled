package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzgk implements Runnable {
    final /* synthetic */ zzgm zza;
    private final zzpl zzb;

    public zzgk(zzgm zzgmVar, zzpl zzplVar) {
        this.zza = zzgmVar;
        this.zzb = zzplVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzpy zzpyVarZzc = this.zzb.zzb().zzc();
        zzgm zzgmVar = this.zza;
        zzqh zzqhVarZzc = this.zzb.zzc();
        zzhv zzhvVar = zzgmVar.zzl;
        this.zza.zzl = zzgmVar.zze.zza(zzpyVarZzc, zzqhVarZzc);
        this.zza.zzm = 2;
        zzhi.zzd("Container " + this.zza.zzb + " loaded during runtime initialization.");
        zzgm zzgmVar2 = this.zza;
        if (zzgmVar2.zzn != null) {
            for (zzgt zzgtVar : zzgmVar2.zzn) {
                zzhi.zzd("Evaluating tags for pending event ".concat(String.valueOf(zzgtVar.zzb())));
                this.zza.zzl.zzf(zzgtVar);
            }
            this.zza.zzn = null;
        }
        this.zza.zzl.zze();
        zzhi.zzd("Runtime initialized successfully for container ".concat(String.valueOf(this.zza.zzb)));
        long jZzb = this.zza.zzk.zzb() + this.zzb.zzb().zza();
        if (zzhvVar == null) {
            zzgm zzgmVar3 = this.zza;
            if (zzgmVar3.zzp && this.zzb.zza() == 1 && jZzb < zzgmVar3.zzj.currentTimeMillis()) {
                zzgm zzgmVar4 = this.zza;
                zzgm.zzr(zzgmVar4, zzgmVar4.zzk.zza());
                return;
            }
        }
        zzgm zzgmVar5 = this.zza;
        zzgm.zzr(zzgmVar5, Math.max(900000L, jZzb - zzgmVar5.zzj.currentTimeMillis()));
    }
}
