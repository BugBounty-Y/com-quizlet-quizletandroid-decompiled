package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzin implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ String zzb;
    final /* synthetic */ zzix zzc;

    public zzin(zzix zzixVar, String str, String str2, String str3) {
        this.zza = str;
        this.zzb = str2;
        this.zzc = zzixVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzhi.zzd("Starting to load container " + this.zza + ".");
        zzix zzixVar = this.zzc;
        if (zzixVar.zzm != 1) {
            zzgp.zzc("Unexpected state - container loading already initiated.", zzixVar.zzc);
            return;
        }
        zzixVar.zzm = 2;
        zzix zzixVar2 = this.zzc;
        zzixVar2.zze.zzc(this.zza, this.zzb, null, new zziv(zzixVar2, null));
    }
}
