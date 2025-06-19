package com.google.android.gms.internal.ads;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.cw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1942cw extends C2227jd implements Yv {
    public final ScheduledExecutorService c;

    public C1942cw(ScheduledExecutorService scheduledExecutorService) {
        super((ExecutorService) scheduledExecutorService);
        this.c = scheduledExecutorService;
    }

    @Override // com.google.android.gms.internal.ads.C2227jd, java.lang.AutoCloseable
    public final /* synthetic */ void close() {
        if (this == ForkJoinPool.commonPool() || isTerminated()) {
            return;
        }
        shutdown();
        boolean zAwaitTermination = false;
        boolean z = false;
        while (!zAwaitTermination) {
            try {
                zAwaitTermination = awaitTermination(1L, TimeUnit.DAYS);
            } catch (InterruptedException unused) {
                if (!z) {
                    shutdownNow();
                }
                z = true;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
    }

    @Override // java.util.concurrent.ScheduledExecutorService
    public final ScheduledFuture schedule(Runnable runnable, long j, TimeUnit timeUnit) {
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(Executors.callable(runnable, null));
        return new ScheduledFutureC1855aw(runnableFutureC2161hw, this.c.schedule(runnableFutureC2161hw, j, timeUnit));
    }

    @Override // java.util.concurrent.ScheduledExecutorService
    public final /* bridge */ /* synthetic */ ScheduledFuture scheduleAtFixedRate(Runnable runnable, long j, long j2, TimeUnit timeUnit) {
        RunnableC1899bw runnableC1899bw = new RunnableC1899bw(runnable);
        return new ScheduledFutureC1855aw(runnableC1899bw, this.c.scheduleAtFixedRate(runnableC1899bw, j, j2, timeUnit));
    }

    @Override // java.util.concurrent.ScheduledExecutorService
    public final /* bridge */ /* synthetic */ ScheduledFuture scheduleWithFixedDelay(Runnable runnable, long j, long j2, TimeUnit timeUnit) {
        RunnableC1899bw runnableC1899bw = new RunnableC1899bw(runnable);
        return new ScheduledFutureC1855aw(runnableC1899bw, this.c.scheduleWithFixedDelay(runnableC1899bw, j, j2, timeUnit));
    }

    @Override // java.util.concurrent.ScheduledExecutorService
    public final ScheduledFuture schedule(Callable callable, long j, TimeUnit timeUnit) {
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(callable);
        return new ScheduledFutureC1855aw(runnableFutureC2161hw, this.c.schedule(runnableFutureC2161hw, j, timeUnit));
    }
}
