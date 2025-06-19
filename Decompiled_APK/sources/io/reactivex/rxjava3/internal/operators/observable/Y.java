package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class Y extends io.reactivex.rxjava3.core.a implements io.reactivex.rxjava3.internal.fuseable.a {
    public final io.reactivex.rxjava3.core.i a;

    public Y(io.reactivex.rxjava3.core.i iVar) {
        this.a = iVar;
    }

    @Override // io.reactivex.rxjava3.internal.fuseable.a
    public final io.reactivex.rxjava3.core.i c() {
        return new C4887f(this.a, 3);
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        this.a.c(new X(bVar, 2));
    }
}
