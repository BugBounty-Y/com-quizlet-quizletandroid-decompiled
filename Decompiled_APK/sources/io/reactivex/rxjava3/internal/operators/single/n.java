package io.reactivex.rxjava3.internal.operators.single;

/* loaded from: classes3.dex */
public final class n extends io.reactivex.rxjava3.internal.subscriptions.a implements io.reactivex.rxjava3.core.q {
    public final io.reactivex.rxjava3.core.f a;
    public Object b;
    public io.reactivex.rxjava3.disposables.b c;

    public n(io.reactivex.rxjava3.core.f fVar) {
        this.a = fVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
            this.c = bVar;
            this.a.c(this);
        }
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
        set(4);
        this.b = null;
        this.c.dispose();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        lazySet(32);
        this.b = null;
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        Object obj;
        if (io.reactivex.rxjava3.internal.subscriptions.c.c(j)) {
            do {
                int i = get();
                if ((i & (-2)) != 0) {
                    return;
                }
                if (i == 1) {
                    if (!compareAndSet(1, 3) || (obj = this.b) == null) {
                        return;
                    }
                    this.b = null;
                    io.reactivex.rxjava3.core.f fVar = this.a;
                    fVar.b(obj);
                    if (get() != 4) {
                        fVar.onComplete();
                        return;
                    }
                    return;
                }
            } while (!compareAndSet(0, 2));
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return get() != 16;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.a.onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        int i = get();
        do {
            io.reactivex.rxjava3.core.f fVar = this.a;
            if (i == 8) {
                this.b = obj;
                lazySet(16);
                fVar.b(null);
                if (get() != 4) {
                    fVar.onComplete();
                    return;
                }
                return;
            }
            if ((i & (-3)) != 0) {
                return;
            }
            if (i == 2) {
                lazySet(3);
                fVar.b(obj);
                if (get() != 4) {
                    fVar.onComplete();
                    return;
                }
                return;
            }
            this.b = obj;
            if (compareAndSet(0, 1)) {
                return;
            } else {
                i = get();
            }
        } while (i != 4);
        this.b = null;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        if (get() != 16) {
            return null;
        }
        lazySet(32);
        Object obj = this.b;
        this.b = null;
        return obj;
    }
}
