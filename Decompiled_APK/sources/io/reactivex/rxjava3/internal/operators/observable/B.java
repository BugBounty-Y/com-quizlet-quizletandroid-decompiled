package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class B extends AbstractC4882a {
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.d c;
    public final io.reactivex.rxjava3.functions.a d;
    public final io.reactivex.rxjava3.functions.a e;

    public B(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar, io.reactivex.rxjava3.functions.a aVar2) {
        super(iVar);
        this.b = dVar;
        this.c = dVar2;
        this.d = aVar;
        this.e = aVar2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        this.a.c(new A(lVar, this.b, this.c, this.d, this.e));
    }
}
