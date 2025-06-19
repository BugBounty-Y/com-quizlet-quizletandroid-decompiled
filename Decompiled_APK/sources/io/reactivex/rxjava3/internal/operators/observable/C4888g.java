package io.reactivex.rxjava3.internal.operators.observable;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4888g extends io.reactivex.rxjava3.core.p implements io.reactivex.rxjava3.internal.fuseable.a {
    public final J a;

    public C4888g(J j) {
        this.a = j;
    }

    @Override // io.reactivex.rxjava3.internal.fuseable.a
    public final io.reactivex.rxjava3.core.i c() {
        return new C4887f(this.a, 0);
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        this.a.c(new C4886e(qVar, 1));
    }
}
