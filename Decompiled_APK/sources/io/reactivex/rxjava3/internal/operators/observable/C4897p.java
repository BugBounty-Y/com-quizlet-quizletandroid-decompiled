package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4897p extends AtomicReference implements io.reactivex.rxjava3.core.l {
    public final io.reactivex.rxjava3.core.l a;
    public final C4898q b;

    public C4897p(io.reactivex.rxjava3.core.l lVar, C4898q c4898q) {
        this.a = lVar;
        this.b = c4898q;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        this.a.b(obj);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        C4898q c4898q = this.b;
        c4898q.h = false;
        c4898q.c();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        C4898q c4898q = this.b;
        if (c4898q.d.c(th)) {
            c4898q.g.dispose();
            c4898q.h = false;
            c4898q.c();
        }
    }
}
