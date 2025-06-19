package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class C extends AbstractC4882a {
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.a c;

    public C(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.a aVar) {
        super(iVar);
        this.b = dVar;
        this.c = aVar;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        this.a.c(new io.reactivex.rxjava3.internal.observers.g(lVar, this.b, this.c, 0));
    }
}
