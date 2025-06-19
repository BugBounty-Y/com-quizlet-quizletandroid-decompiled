package com.google.android.gms.internal.ads;

import java.util.concurrent.Delayed;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.aw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ScheduledFutureC1855aw extends AbstractC2025es implements ScheduledFuture, com.google.common.util.concurrent.e, Future {
    public final AbstractC2460ov c;
    public final ScheduledFuture d;

    public ScheduledFutureC1855aw(AbstractC2460ov abstractC2460ov, ScheduledFuture scheduledFuture) {
        super(4);
        this.c = abstractC2460ov;
        this.d = scheduledFuture;
    }

    @Override // com.google.common.util.concurrent.e
    public final void a(Runnable runnable, Executor executor) {
        this.c.a(runnable, executor);
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        boolean zCancel = this.c.cancel(z);
        if (zCancel) {
            this.d.cancel(z);
        }
        return zCancel;
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Delayed delayed) {
        return this.d.compareTo(delayed);
    }

    @Override // java.util.concurrent.Future
    public final Object get() {
        return this.c.get();
    }

    @Override // java.util.concurrent.Delayed
    public final long getDelay(TimeUnit timeUnit) {
        return this.d.getDelay(timeUnit);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final /* synthetic */ Object h() {
        return this.c;
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.c.isCancelled();
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.c.isDone();
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return this.c.get(j, timeUnit);
    }
}
