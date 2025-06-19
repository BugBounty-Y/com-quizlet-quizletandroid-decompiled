package com.google.android.gms.internal.gtm;

import android.content.ComponentName;

/* loaded from: classes2.dex */
final class zzbz implements Runnable {
    final /* synthetic */ ComponentName zza;
    final /* synthetic */ zzca zzb;

    public zzbz(zzca zzcaVar, ComponentName componentName) {
        this.zza = componentName;
        this.zzb = zzcaVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzcb.zzb(this.zzb.zza, this.zza);
    }
}
