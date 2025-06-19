package io.reactivex.rxjava3.subjects;

import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class i extends AtomicBoolean implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final j b;

    public i(io.reactivex.rxjava3.core.l lVar, j jVar) {
        this.a = lVar;
        this.b = jVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (compareAndSet(false, true)) {
            this.b.z(this);
        }
    }
}
