package io.reactivex.rxjava3.internal.operators.flowable;

import io.reactivex.rxjava3.core.l;

/* loaded from: classes3.dex */
public final class d implements l, org.reactivestreams.b {
    public final io.reactivex.rxjava3.core.f a;
    public io.reactivex.rxjava3.disposables.b b;

    public d(io.reactivex.rxjava3.core.f fVar) {
        this.a = fVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.b = bVar;
        this.a.c(this);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        this.a.b(obj);
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
        this.b.dispose();
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.a.onError(th);
    }
}
