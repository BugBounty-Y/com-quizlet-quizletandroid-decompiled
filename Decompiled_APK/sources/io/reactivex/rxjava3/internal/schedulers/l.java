package io.reactivex.rxjava3.internal.schedulers;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class l extends io.reactivex.rxjava3.core.n implements Runnable {
    public final k b;
    public final m c;
    public final AtomicBoolean d = new AtomicBoolean();
    public final io.reactivex.rxjava3.disposables.a a = new io.reactivex.rxjava3.disposables.a();

    public l(k kVar) {
        m mVar;
        m mVar2;
        this.b = kVar;
        if (kVar.c.b) {
            mVar2 = n.f;
        } else {
            while (true) {
                if (kVar.b.isEmpty()) {
                    mVar = new m(kVar.f);
                    kVar.c.b(mVar);
                    break;
                } else {
                    mVar = (m) kVar.b.poll();
                    if (mVar != null) {
                        break;
                    }
                }
            }
            mVar2 = mVar;
        }
        this.c = mVar2;
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        return this.a.b ? io.reactivex.rxjava3.internal.disposables.b.a : this.c.c(runnable, j, timeUnit, this.a);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.d.compareAndSet(false, true)) {
            this.a.dispose();
            if (n.g) {
                this.c.c(this, 0L, TimeUnit.NANOSECONDS, null);
                return;
            }
            k kVar = this.b;
            kVar.getClass();
            long jNanoTime = System.nanoTime() + kVar.a;
            m mVar = this.c;
            mVar.c = jNanoTime;
            kVar.b.offer(mVar);
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        k kVar = this.b;
        kVar.getClass();
        long jNanoTime = System.nanoTime() + kVar.a;
        m mVar = this.c;
        mVar.c = jNanoTime;
        kVar.b.offer(mVar);
    }
}
