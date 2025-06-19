package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class d extends io.reactivex.rxjava3.core.o {
    public static final b b;
    public static final q c;
    public static final int d;
    public static final c e;
    public final AtomicReference a;

    static {
        int iAvailableProcessors = Runtime.getRuntime().availableProcessors();
        int iIntValue = Integer.getInteger("rx3.computation-threads", 0).intValue();
        if (iIntValue > 0 && iIntValue <= iAvailableProcessors) {
            iAvailableProcessors = iIntValue;
        }
        d = iAvailableProcessors;
        c cVar = new c(new q("RxComputationShutdown"));
        e = cVar;
        cVar.dispose();
        q qVar = new q("RxComputationThreadPool", Math.max(1, Math.min(10, Integer.getInteger("rx3.computation-priority", 5).intValue())), true);
        c = qVar;
        b bVar = new b(0, qVar);
        b = bVar;
        for (c cVar2 : bVar.b) {
            cVar2.dispose();
        }
    }

    public d() {
        AtomicReference atomicReference;
        q qVar = c;
        b bVar = b;
        this.a = new AtomicReference(bVar);
        b bVar2 = new b(d, qVar);
        do {
            atomicReference = this.a;
            if (atomicReference.compareAndSet(bVar, bVar2)) {
                return;
            }
        } while (atomicReference.get() == bVar);
        for (c cVar : bVar2.b) {
            cVar.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.core.n a() {
        c cVar;
        b bVar = (b) this.a.get();
        int i = bVar.a;
        if (i == 0) {
            cVar = e;
        } else {
            long j = bVar.c;
            bVar.c = 1 + j;
            cVar = bVar.b[(int) (j % i)];
        }
        return new a(cVar);
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.disposables.b c(Runnable runnable, long j, TimeUnit timeUnit) {
        c cVar;
        b bVar = (b) this.a.get();
        int i = bVar.a;
        if (i == 0) {
            cVar = e;
        } else {
            long j2 = bVar.c;
            bVar.c = 1 + j2;
            cVar = bVar.b[(int) (j2 % i)];
        }
        cVar.getClass();
        Objects.requireNonNull(runnable, "run is null");
        r rVar = new r(runnable);
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = cVar.a;
        try {
            rVar.a(j <= 0 ? scheduledThreadPoolExecutor.submit(rVar) : scheduledThreadPoolExecutor.schedule(rVar, j, timeUnit));
            return rVar;
        } catch (RejectedExecutionException e2) {
            C7.c(e2);
            return io.reactivex.rxjava3.internal.disposables.b.a;
        }
    }
}
