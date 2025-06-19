package io.reactivex.rxjava3.subjects;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class g extends AtomicReference implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.h a;

    public g(io.reactivex.rxjava3.core.h hVar, h hVar2) {
        this.a = hVar;
        lazySet(hVar2);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        h hVar = (h) getAndSet(null);
        if (hVar != null) {
            hVar.i(this);
        }
    }
}
