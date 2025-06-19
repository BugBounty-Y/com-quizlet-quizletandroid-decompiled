package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzbl implements Runnable {
    final /* synthetic */ zzek zza;
    final /* synthetic */ zzbp zzb;

    public zzbl(zzbp zzbpVar, zzek zzekVar) {
        this.zza = zzekVar;
        this.zzb = zzbpVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        this.zzb.zza.zzj(this.zza);
    }
}
