package com.google.android.gms.internal.gtm;

import java.lang.Thread;

/* loaded from: classes2.dex */
final class zzbt implements Thread.UncaughtExceptionHandler {
    final /* synthetic */ zzbu zza;

    public zzbt(zzbu zzbuVar) {
        this.zza = zzbuVar;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread thread, Throwable th) {
        zzeo zzeoVarZzn = this.zza.zzn();
        if (zzeoVarZzn != null) {
            zzeoVarZzn.zzJ("Job execution failed", th);
        }
    }
}
