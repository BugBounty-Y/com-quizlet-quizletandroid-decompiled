package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class u extends a {
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.d c;
    public final io.reactivex.rxjava3.functions.d d;
    public final io.reactivex.rxjava3.functions.a e;

    public u(io.reactivex.rxjava3.core.g gVar, io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.d dVar3, io.reactivex.rxjava3.functions.a aVar) {
        super(gVar);
        this.b = dVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = aVar;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        this.a.e(new com.quizlet.infra.legacysyncengine.datasources.s(6, hVar, this));
    }
}
