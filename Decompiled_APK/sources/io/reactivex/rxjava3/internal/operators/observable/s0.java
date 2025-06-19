package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class s0 extends AtomicReference implements io.reactivex.rxjava3.core.l {
    public final /* synthetic */ t0 a;

    public s0(t0 t0Var) {
        this.a = t0Var;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.internal.disposables.a.a(this);
        t0 t0Var = this.a;
        io.reactivex.rxjava3.internal.disposables.a.a(t0Var.b);
        if (t0Var.getAndIncrement() == 0) {
            t0Var.d.g(t0Var.a);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        t0 t0Var = this.a;
        io.reactivex.rxjava3.internal.disposables.a.a(t0Var.b);
        if (t0Var.getAndIncrement() == 0) {
            t0Var.d.g(t0Var.a);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        t0 t0Var = this.a;
        io.reactivex.rxjava3.internal.disposables.a.a(t0Var.b);
        io.reactivex.rxjava3.internal.util.b bVar = t0Var.d;
        if (bVar.c(th) && t0Var.getAndIncrement() == 0) {
            bVar.g(t0Var.a);
        }
    }
}
