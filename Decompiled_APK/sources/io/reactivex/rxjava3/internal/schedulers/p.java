package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.Callable;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public class p extends io.reactivex.rxjava3.core.n {
    public final ScheduledThreadPoolExecutor a;
    public volatile boolean b;

    public p(q qVar) {
        boolean z = t.a;
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1, qVar);
        scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(t.a);
        this.a = scheduledThreadPoolExecutor;
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b a(Runnable runnable) {
        return b(runnable, 0L, null);
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        return this.b ? io.reactivex.rxjava3.internal.disposables.b.a : c(runnable, j, timeUnit, null);
    }

    public final s c(Runnable runnable, long j, TimeUnit timeUnit, io.reactivex.rxjava3.disposables.c cVar) {
        s sVar = new s(runnable, cVar, true);
        if (cVar == null || cVar.b(sVar)) {
            ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = this.a;
            try {
                sVar.a(j <= 0 ? scheduledThreadPoolExecutor.submit((Callable) sVar) : scheduledThreadPoolExecutor.schedule((Callable) sVar, j, timeUnit));
                return sVar;
            } catch (RejectedExecutionException e) {
                if (cVar != null) {
                    cVar.a(sVar);
                }
                C7.c(e);
            }
        }
        return sVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.b) {
            return;
        }
        this.b = true;
        this.a.shutdownNow();
    }
}
