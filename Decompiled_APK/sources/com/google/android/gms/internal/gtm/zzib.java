package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzib implements Runnable {
    final /* synthetic */ zzig zza;

    public zzib(zzig zzigVar) {
        this.zza = zzigVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zza.zzh = false;
        this.zza.zzd.zza();
    }
}
