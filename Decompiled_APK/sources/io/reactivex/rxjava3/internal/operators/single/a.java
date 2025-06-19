package io.reactivex.rxjava3.internal.operators.single;

import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class a extends AtomicBoolean implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.q a;
    public final b b;

    public a(io.reactivex.rxjava3.core.q qVar, b bVar) {
        this.a = qVar;
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (compareAndSet(false, true)) {
            this.b.r(this);
        }
    }
}
