package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class X implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public final Object b;
    public io.reactivex.rxjava3.disposables.b c;

    public /* synthetic */ X(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void c(Object obj) {
    }

    private final void d(Object obj) {
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.l) this.b).a(this);
                    break;
                }
                break;
            case 1:
                this.c = bVar;
                ((io.reactivex.rxjava3.core.l) this.b).a(this);
                break;
            default:
                this.c = bVar;
                ((io.reactivex.rxjava3.core.b) this.b).a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.l) this.b).b(obj);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.c.dispose();
                break;
            case 1:
                this.c.dispose();
                break;
            default:
                this.c.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.l) this.b).onComplete();
                break;
            case 1:
                ((io.reactivex.rxjava3.core.l) this.b).onComplete();
                break;
            default:
                ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.l) this.b).onError(th);
                break;
            case 1:
                ((io.reactivex.rxjava3.core.l) this.b).onError(th);
                break;
            default:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                break;
        }
    }
}
