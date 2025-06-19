package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.TimeUnit;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4902v extends AbstractC4882a {
    public final long b;
    public final TimeUnit c;
    public final io.reactivex.rxjava3.core.o d;

    public C4902v(io.reactivex.rxjava3.core.i iVar, long j, TimeUnit timeUnit, io.reactivex.rxjava3.core.o oVar) {
        super(iVar);
        this.b = j;
        this.c = timeUnit;
        this.d = oVar;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        this.a.c(new C4901u(new io.reactivex.rxjava3.observers.a(lVar), this.b, this.c, this.d.a()));
    }
}
