package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class d0 extends AtomicReference implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;

    public d0(io.reactivex.rxjava3.core.l lVar, e0 e0Var) {
        this.a = lVar;
        lazySet(e0Var);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        e0 e0Var = (e0) getAndSet(null);
        if (e0Var != null) {
            e0Var.d(this);
        }
    }
}
