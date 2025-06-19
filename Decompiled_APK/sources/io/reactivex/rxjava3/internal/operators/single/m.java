package io.reactivex.rxjava3.internal.operators.single;

import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class m extends io.reactivex.rxjava3.core.p {
    public final io.reactivex.rxjava3.core.p a;
    public final long b;
    public final io.reactivex.rxjava3.core.o c;
    public final io.reactivex.rxjava3.internal.operators.flowable.b d;

    public m(io.reactivex.rxjava3.core.p pVar, long j, io.reactivex.rxjava3.core.o oVar, io.reactivex.rxjava3.internal.operators.flowable.b bVar) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.a = pVar;
        this.b = j;
        this.c = oVar;
        this.d = bVar;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = this.d;
        long j = this.b;
        l lVar = new l(qVar, bVar, j);
        qVar.a(lVar);
        io.reactivex.rxjava3.internal.disposables.a.c(lVar.b, this.c.c(lVar, j, timeUnit));
        this.a.j(lVar);
    }
}
