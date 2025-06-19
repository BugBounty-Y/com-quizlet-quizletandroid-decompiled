package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzhk implements zzih {
    final /* synthetic */ zzhm zza;

    public zzhk(zzhm zzhmVar) {
        this.zza = zzhmVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzih
    public final void zza(zzgv zzgvVar) {
        this.zza.zzo(zzgvVar.zzb());
        zzhi.zzd("Permanent failure dispatching hitId: " + zzgvVar.zzb());
    }

    @Override // com.google.android.gms.internal.gtm.zzih
    public final void zzb(zzgv zzgvVar) {
        long jZza = zzgvVar.zza();
        if (jZza == 0) {
            zzhm.zzl(this.zza, zzgvVar.zzb(), this.zza.zzj.currentTimeMillis());
            return;
        }
        if (jZza + 14400000 < this.zza.zzj.currentTimeMillis()) {
            this.zza.zzo(zzgvVar.zzb());
            zzhi.zzd("Giving up on failed hitId: " + zzgvVar.zzb());
        }
    }
}
