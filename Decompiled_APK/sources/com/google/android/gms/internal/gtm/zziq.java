package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zziq implements Runnable {
    final /* synthetic */ zzir zza;

    public zziq(zzir zzirVar) {
        this.zza = zzirVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzhi.zzd("App's UI deactivated. Dispatching hits.");
        this.zza.zza.zze.zza();
    }
}
