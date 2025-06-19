package io.reactivex.rxjava3.subjects;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class m extends AtomicInteger implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final p b;
    public Serializable c;
    public volatile boolean d;

    public m(io.reactivex.rxjava3.core.l lVar, p pVar) {
        this.a = lVar;
        this.b = pVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.d) {
            return;
        }
        this.d = true;
        this.b.A(this);
    }
}
