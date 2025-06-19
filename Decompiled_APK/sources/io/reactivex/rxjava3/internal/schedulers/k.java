package io.reactivex.rxjava3.internal.schedulers;

import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class k implements Runnable {
    public final long a;
    public final ConcurrentLinkedQueue b;
    public final io.reactivex.rxjava3.disposables.a c;
    public final ScheduledExecutorService d;
    public final ScheduledFuture e;
    public final q f;

    public k(long j, TimeUnit timeUnit, q qVar) {
        k kVar;
        ScheduledExecutorService scheduledExecutorServiceNewScheduledThreadPool;
        ScheduledFuture<?> scheduledFutureScheduleWithFixedDelay;
        long nanos = timeUnit != null ? timeUnit.toNanos(j) : 0L;
        this.a = nanos;
        this.b = new ConcurrentLinkedQueue();
        this.c = new io.reactivex.rxjava3.disposables.a();
        this.f = qVar;
        if (timeUnit != null) {
            scheduledExecutorServiceNewScheduledThreadPool = Executors.newScheduledThreadPool(1, n.c);
            kVar = this;
            scheduledFutureScheduleWithFixedDelay = scheduledExecutorServiceNewScheduledThreadPool.scheduleWithFixedDelay(kVar, nanos, nanos, TimeUnit.NANOSECONDS);
        } else {
            kVar = this;
            scheduledExecutorServiceNewScheduledThreadPool = null;
            scheduledFutureScheduleWithFixedDelay = null;
        }
        kVar.d = scheduledExecutorServiceNewScheduledThreadPool;
        kVar.e = scheduledFutureScheduleWithFixedDelay;
    }

    @Override // java.lang.Runnable
    public final void run() {
        ConcurrentLinkedQueue concurrentLinkedQueue = this.b;
        if (concurrentLinkedQueue.isEmpty()) {
            return;
        }
        long jNanoTime = System.nanoTime();
        Iterator it2 = concurrentLinkedQueue.iterator();
        while (it2.hasNext()) {
            m mVar = (m) it2.next();
            if (mVar.c > jNanoTime) {
                return;
            }
            if (concurrentLinkedQueue.remove(mVar)) {
                this.c.a(mVar);
            }
        }
    }
}
