package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class u0 extends AtomicReference implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b, Runnable {
    public final io.reactivex.rxjava3.observers.a a;
    public final long b;
    public final TimeUnit c;
    public final io.reactivex.rxjava3.core.n d;
    public io.reactivex.rxjava3.disposables.b e;
    public volatile boolean f;

    public u0(io.reactivex.rxjava3.observers.a aVar, io.reactivex.rxjava3.core.n nVar) {
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        this.a = aVar;
        this.b = 2000L;
        this.c = timeUnit;
        this.d = nVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.e, bVar)) {
            this.e = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.f) {
            return;
        }
        this.f = true;
        this.a.b(obj);
        io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) get();
        if (bVar != null) {
            bVar.dispose();
        }
        io.reactivex.rxjava3.internal.disposables.a.c(this, this.d.b(this, this.b, this.c));
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e.dispose();
        this.d.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.a.onComplete();
        this.d.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.a.onError(th);
        this.d.dispose();
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.f = false;
    }
}
