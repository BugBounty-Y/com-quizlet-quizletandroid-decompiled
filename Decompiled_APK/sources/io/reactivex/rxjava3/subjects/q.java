package io.reactivex.rxjava3.subjects;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class q extends AtomicReference implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.q a;

    public q(io.reactivex.rxjava3.core.q qVar, r rVar) {
        this.a = qVar;
        lazySet(rVar);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        r rVar = (r) getAndSet(null);
        if (rVar != null) {
            rVar.t(this);
        }
    }
}
