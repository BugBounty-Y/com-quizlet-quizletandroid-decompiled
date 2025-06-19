package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzge implements Runnable {
    final /* synthetic */ zzgm zza;

    public zzge(zzgm zzgmVar) {
        this.zza = zzgmVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zza.zzm == 2) {
            this.zza.zzl.zze();
        }
    }
}
