package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class y0 implements io.reactivex.rxjava3.core.l {
    public final x0 a;
    public final io.reactivex.rxjava3.operators.g b;
    public volatile boolean c;
    public Throwable d;
    public final AtomicReference e = new AtomicReference();

    public y0(x0 x0Var, int i) {
        this.a = x0Var;
        this.b = new io.reactivex.rxjava3.operators.g(i);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this.e, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        this.b.offer(obj);
        this.a.b();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.c = true;
        this.a.b();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.d = th;
        this.c = true;
        this.a.b();
    }
}
