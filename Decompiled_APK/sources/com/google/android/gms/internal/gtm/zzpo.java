package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzpo implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ String zzb;
    final /* synthetic */ zzpa zzc;
    final /* synthetic */ zzpq zzd;

    public zzpo(zzpq zzpqVar, String str, String str2, zzpa zzpaVar) {
        this.zza = str;
        this.zzb = str2;
        this.zzc = zzpaVar;
        this.zzd = zzpqVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zzd.zzd(this.zza, this.zzb, this.zzc);
    }
}
