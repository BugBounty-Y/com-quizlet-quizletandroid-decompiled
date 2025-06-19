package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class k0 extends AtomicInteger implements io.reactivex.rxjava3.operators.a, Runnable {
    public final io.reactivex.rxjava3.core.l a;
    public final Object b;

    public k0(io.reactivex.rxjava3.core.l lVar, Object obj) {
        this.a = lVar;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        lazySet(3);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        set(3);
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        lazySet(1);
        return 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return get() != 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        throw new UnsupportedOperationException("Should not be called!");
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        if (get() != 1) {
            return null;
        }
        lazySet(3);
        return this.b;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (get() == 0 && compareAndSet(0, 2)) {
            Object obj = this.b;
            io.reactivex.rxjava3.core.l lVar = this.a;
            lVar.b(obj);
            if (get() == 2) {
                lazySet(3);
                lVar.onComplete();
            }
        }
    }
}
