package io.reactivex.rxjava3.subjects;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class e extends AtomicReference implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.b a;

    public e(io.reactivex.rxjava3.core.b bVar, f fVar) {
        this.a = bVar;
        lazySet(fVar);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        f fVar = (f) getAndSet(null);
        if (fVar != null) {
            fVar.i(this);
        }
    }
}
