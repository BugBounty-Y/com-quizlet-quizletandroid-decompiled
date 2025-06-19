package com.google.android.gms.internal.gtm;

import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
final class zzck implements Callable {
    final /* synthetic */ zzcm zza;

    public zzck(zzcm zzcmVar) {
        this.zza = zzcmVar;
    }

    @Override // java.util.concurrent.Callable
    public final /* synthetic */ Object call() throws Exception {
        return this.zza.zzc();
    }
}
