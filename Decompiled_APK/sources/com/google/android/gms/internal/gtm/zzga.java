package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzga implements Runnable {
    final /* synthetic */ zzgc zza;

    public zzga(zzgc zzgcVar) {
        this.zza = zzgcVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        zzgc.zze(this.zza);
    }
}
