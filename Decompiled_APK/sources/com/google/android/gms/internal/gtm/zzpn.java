package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzpn implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ zzpa zzb;
    final /* synthetic */ zzpq zzc;

    public zzpn(zzpq zzpqVar, String str, zzpa zzpaVar) {
        this.zza = str;
        this.zzb = zzpaVar;
        this.zzc = zzpqVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zzc.zzf(this.zza, this.zzb);
    }
}
