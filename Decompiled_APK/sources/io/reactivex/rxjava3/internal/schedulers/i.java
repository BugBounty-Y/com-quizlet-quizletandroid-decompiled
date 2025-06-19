package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class i extends io.reactivex.rxjava3.core.n implements Runnable {
    public final Executor c;
    public volatile boolean e;
    public final AtomicInteger f = new AtomicInteger();
    public final io.reactivex.rxjava3.disposables.a g = new io.reactivex.rxjava3.disposables.a();
    public final com.quizlet.remote.model.progress.e d = new com.quizlet.remote.model.progress.e();
    public final boolean a = true;
    public final boolean b = true;

    public i(Executor executor) {
        this.c = executor;
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b a(Runnable runnable) {
        io.reactivex.rxjava3.disposables.b gVar;
        boolean z = this.e;
        io.reactivex.rxjava3.internal.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
        if (z) {
            return bVar;
        }
        if (this.a) {
            gVar = new h(runnable, this.g);
            this.g.b(gVar);
        } else {
            gVar = new g(runnable);
        }
        com.quizlet.remote.model.progress.e eVar = this.d;
        eVar.getClass();
        io.reactivex.rxjava3.internal.queue.a aVar = new io.reactivex.rxjava3.internal.queue.a();
        aVar.a = gVar;
        ((io.reactivex.rxjava3.internal.queue.a) ((AtomicReference) eVar.a).getAndSet(aVar)).lazySet(aVar);
        if (this.f.getAndIncrement() != 0) {
            return gVar;
        }
        try {
            this.c.execute(this);
            return gVar;
        } catch (RejectedExecutionException e) {
            this.e = true;
            this.d.clear();
            C7.c(e);
            return bVar;
        }
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        if (j <= 0) {
            return a(runnable);
        }
        boolean z = this.e;
        io.reactivex.rxjava3.internal.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
        if (z) {
            return bVar;
        }
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(2);
        io.reactivex.rxjava3.disposables.d dVar2 = new io.reactivex.rxjava3.disposables.d(2);
        dVar2.lazySet(dVar);
        s sVar = new s(new androidx.core.provider.k(24, this, dVar2, runnable, false), this.g, this.a);
        this.g.b(sVar);
        Executor executor = this.c;
        if (executor instanceof ScheduledExecutorService) {
            try {
                sVar.a(((ScheduledExecutorService) executor).schedule((Callable) sVar, j, timeUnit));
            } catch (RejectedExecutionException e) {
                this.e = true;
                C7.c(e);
                return bVar;
            }
        } else {
            sVar.a(new e(j.a.c(sVar, j, timeUnit)));
        }
        io.reactivex.rxjava3.internal.disposables.a.c(dVar, sVar);
        return dVar2;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.e) {
            return;
        }
        this.e = true;
        this.g.dispose();
        if (this.f.getAndIncrement() == 0) {
            this.d.clear();
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.b) {
            com.quizlet.remote.model.progress.e eVar = this.d;
            if (this.e) {
                eVar.clear();
                return;
            }
            ((Runnable) eVar.poll()).run();
            if (this.e) {
                eVar.clear();
                return;
            } else {
                if (this.f.decrementAndGet() != 0) {
                    this.c.execute(this);
                    return;
                }
                return;
            }
        }
        com.quizlet.remote.model.progress.e eVar2 = this.d;
        int iAddAndGet = 1;
        while (!this.e) {
            do {
                Runnable runnable = (Runnable) eVar2.poll();
                if (runnable != null) {
                    runnable.run();
                } else if (this.e) {
                    eVar2.clear();
                    return;
                } else {
                    iAddAndGet = this.f.addAndGet(-iAddAndGet);
                    if (iAddAndGet == 0) {
                        return;
                    }
                }
            } while (!this.e);
            eVar2.clear();
            return;
        }
        eVar2.clear();
    }
}
