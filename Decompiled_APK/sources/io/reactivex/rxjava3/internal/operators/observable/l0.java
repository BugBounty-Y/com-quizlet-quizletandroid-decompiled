package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class l0 implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public long b = 1;
    public io.reactivex.rxjava3.disposables.b c;

    public l0(io.reactivex.rxjava3.core.l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
            this.c = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        long j = this.b;
        if (j != 0) {
            this.b = j - 1;
        } else {
            this.a.b(obj);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.c.dispose();
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
