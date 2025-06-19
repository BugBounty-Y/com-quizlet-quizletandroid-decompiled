package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class t0 extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final AtomicReference b = new AtomicReference();
    public final s0 c = new s0(this);
    public final io.reactivex.rxjava3.internal.util.b d = new io.reactivex.rxjava3.internal.util.b();

    public t0(io.reactivex.rxjava3.core.l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this.b, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (get() == 0 && compareAndSet(0, 1)) {
            io.reactivex.rxjava3.core.l lVar = this.a;
            lVar.b(obj);
            if (decrementAndGet() != 0) {
                this.d.g(lVar);
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this.b);
        io.reactivex.rxjava3.internal.disposables.a.a(this.c);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        io.reactivex.rxjava3.internal.disposables.a.a(this.c);
        if (getAndIncrement() == 0) {
            this.d.g(this.a);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.disposables.a.a(this.c);
        io.reactivex.rxjava3.internal.util.b bVar = this.d;
        if (bVar.c(th) && getAndIncrement() == 0) {
            bVar.g(this.a);
        }
    }
}
