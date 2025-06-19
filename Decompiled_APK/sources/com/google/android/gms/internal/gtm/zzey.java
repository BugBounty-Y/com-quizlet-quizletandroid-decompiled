package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzey implements zzcy {
    final /* synthetic */ Runnable zza;
    final /* synthetic */ zzfa zzb;

    public zzey(zzfa zzfaVar, Runnable runnable) {
        this.zza = runnable;
        this.zzb = zzfaVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzcy
    public final void zza(Throwable th) {
        this.zzb.zzb.post(this.zza);
    }
}
