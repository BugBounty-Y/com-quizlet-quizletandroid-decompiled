package io.reactivex.rxjava3.internal.operators.completable;

import com.quizlet.infra.legacysyncengine.datasources.s;

/* loaded from: classes3.dex */
public final class i extends io.reactivex.rxjava3.core.a {
    public final io.reactivex.rxjava3.core.a a;
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.d c;
    public final io.reactivex.rxjava3.functions.a d;
    public final io.reactivex.rxjava3.functions.a e;

    public i(io.reactivex.rxjava3.core.a aVar, io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar2, io.reactivex.rxjava3.functions.a aVar3) {
        this.a = aVar;
        this.b = dVar;
        this.c = dVar2;
        this.d = aVar2;
        this.e = aVar3;
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        this.a.b(new s(this, bVar));
    }
}
