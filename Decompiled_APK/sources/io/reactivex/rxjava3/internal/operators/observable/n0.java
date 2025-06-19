package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class n0 implements io.reactivex.rxjava3.core.l {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.core.i b;
    public boolean d = true;
    public final io.reactivex.rxjava3.disposables.d c = new io.reactivex.rxjava3.disposables.d(2);

    public n0(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.core.i iVar) {
        this.a = lVar;
        this.b = iVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.disposables.d dVar = this.c;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.d(dVar, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.d) {
            this.d = false;
        }
        this.a.b(obj);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (!this.d) {
            this.a.onComplete();
        } else {
            this.d = false;
            this.b.c(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.a.onError(th);
    }
}
