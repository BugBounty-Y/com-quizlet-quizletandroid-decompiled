package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzgf implements Runnable {
    final /* synthetic */ zzgm zza;

    public zzgf(zzgm zzgmVar) {
        this.zza = zzgmVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzgm zzgmVar = this.zza;
        zzgmVar.zzg.execute(new zzgj(zzgmVar, null));
    }
}
