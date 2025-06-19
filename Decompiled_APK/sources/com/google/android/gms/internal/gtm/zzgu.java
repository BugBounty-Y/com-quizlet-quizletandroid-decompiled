package com.google.android.gms.internal.gtm;

import android.content.Context;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class zzgu extends ThreadPoolExecutor {
    private final Context zza;

    public zzgu(Context context, int i, int i2, long j, TimeUnit timeUnit, BlockingQueue blockingQueue, ThreadFactory threadFactory) {
        super(1, 1, 0L, timeUnit, (BlockingQueue<Runnable>) blockingQueue, threadFactory);
        this.zza = context;
    }

    @Override // java.util.concurrent.ThreadPoolExecutor
    public final void afterExecute(Runnable runnable, Throwable th) {
        if (th != null) {
            zzgp.zzb("Uncaught exception: ", th, this.zza);
        }
    }
}
