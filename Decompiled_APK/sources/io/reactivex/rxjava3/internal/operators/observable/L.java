package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class L extends io.reactivex.rxjava3.core.a implements io.reactivex.rxjava3.internal.fuseable.a {
    public final io.reactivex.rxjava3.core.i a;
    public final io.reactivex.rxjava3.functions.h b;

    public L(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = iVar;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.internal.fuseable.a
    public final io.reactivex.rxjava3.core.i c() {
        return new J(this.a, this.b, 0);
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        this.a.c(new K(bVar, this.b));
    }
}
