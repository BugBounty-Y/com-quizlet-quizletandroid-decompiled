package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzbj implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ Runnable zzb;
    final /* synthetic */ zzbp zzc;

    public zzbj(zzbp zzbpVar, String str, Runnable runnable) {
        this.zza = str;
        this.zzb = runnable;
        this.zzc = zzbpVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zzc.zza.zzn(this.zza);
        this.zzb.run();
    }
}
