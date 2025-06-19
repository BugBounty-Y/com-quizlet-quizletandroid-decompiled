package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class v extends io.reactivex.rxjava3.core.o {
    public static final q b;
    public static final ScheduledExecutorService c;
    public final AtomicReference a;

    static {
        ScheduledExecutorService scheduledExecutorServiceNewScheduledThreadPool = Executors.newScheduledThreadPool(0);
        c = scheduledExecutorServiceNewScheduledThreadPool;
        scheduledExecutorServiceNewScheduledThreadPool.shutdown();
        b = new q("RxSingleScheduler", Math.max(1, Math.min(10, Integer.getInteger("rx3.single-priority", 5).intValue())), true);
    }

    public v() {
        AtomicReference atomicReference = new AtomicReference();
        this.a = atomicReference;
        boolean z = t.a;
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1, b);
        scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(t.a);
        atomicReference.lazySet(scheduledThreadPoolExecutor);
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.core.n a() {
        return new u((ScheduledExecutorService) this.a.get());
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.disposables.b c(Runnable runnable, long j, TimeUnit timeUnit) {
        Objects.requireNonNull(runnable, "run is null");
        r rVar = new r(runnable);
        AtomicReference atomicReference = this.a;
        try {
            rVar.a(j <= 0 ? ((ScheduledExecutorService) atomicReference.get()).submit(rVar) : ((ScheduledExecutorService) atomicReference.get()).schedule(rVar, j, timeUnit));
            return rVar;
        } catch (RejectedExecutionException e) {
            C7.c(e);
            return io.reactivex.rxjava3.internal.disposables.b.a;
        }
    }
}
