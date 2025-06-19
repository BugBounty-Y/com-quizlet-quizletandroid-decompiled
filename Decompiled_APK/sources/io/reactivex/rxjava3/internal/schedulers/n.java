package io.reactivex.rxjava3.internal.schedulers;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class n extends io.reactivex.rxjava3.core.o {
    public static final q b;
    public static final q c;
    public static final m f;
    public static final boolean g;
    public static final k h;
    public final AtomicReference a;
    public static final TimeUnit e = TimeUnit.SECONDS;
    public static final long d = Long.getLong("rx3.io-keep-alive-time", 60).longValue();

    static {
        m mVar = new m(new q("RxCachedThreadSchedulerShutdown"));
        f = mVar;
        mVar.dispose();
        int iMax = Math.max(1, Math.min(10, Integer.getInteger("rx3.io-priority", 5).intValue()));
        q qVar = new q("RxCachedThreadScheduler", iMax, false);
        b = qVar;
        c = new q("RxCachedWorkerPoolEvictor", iMax, false);
        g = Boolean.getBoolean("rx3.io-scheduled-release");
        k kVar = new k(0L, null, qVar);
        h = kVar;
        kVar.c.dispose();
        ScheduledFuture scheduledFuture = kVar.e;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        ScheduledExecutorService scheduledExecutorService = kVar.d;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdownNow();
        }
    }

    public n() {
        AtomicReference atomicReference;
        q qVar = b;
        k kVar = h;
        this.a = new AtomicReference(kVar);
        k kVar2 = new k(d, e, qVar);
        do {
            atomicReference = this.a;
            if (atomicReference.compareAndSet(kVar, kVar2)) {
                return;
            }
        } while (atomicReference.get() == kVar);
        kVar2.c.dispose();
        ScheduledFuture scheduledFuture = kVar2.e;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        ScheduledExecutorService scheduledExecutorService = kVar2.d;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdownNow();
        }
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.core.n a() {
        return new l((k) this.a.get());
    }
}
