package io.reactivex.rxjava3.internal.operators.completable;

import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.core.q;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class g extends AtomicReference implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b, Runnable, q {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public Object d;

    public g(io.reactivex.rxjava3.core.b bVar, o oVar) {
        this.a = 0;
        this.b = bVar;
        this.c = oVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((io.reactivex.rxjava3.core.b) this.b).a(this);
                    break;
                }
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                io.reactivex.rxjava3.disposables.d dVar = (io.reactivex.rxjava3.disposables.d) this.c;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.a(dVar);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                io.reactivex.rxjava3.disposables.d dVar2 = (io.reactivex.rxjava3.disposables.d) this.c;
                dVar2.getClass();
                io.reactivex.rxjava3.internal.disposables.a.a(dVar2);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.c(this, ((o) this.c).b(this));
                break;
            default:
                ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.d = th;
                io.reactivex.rxjava3.internal.disposables.a.c(this, ((o) this.c).b(this));
                break;
            case 1:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                break;
            default:
                ((q) this.b).onError(th);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((q) this.b).onSuccess(obj);
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Throwable th = (Throwable) this.d;
                io.reactivex.rxjava3.core.b bVar = (io.reactivex.rxjava3.core.b) this.b;
                if (th == null) {
                    bVar.onComplete();
                    break;
                } else {
                    this.d = null;
                    bVar.onError(th);
                    break;
                }
            case 1:
                ((io.reactivex.rxjava3.core.a) this.d).b(this);
                break;
            default:
                ((p) this.d).j(this);
                break;
        }
    }

    public g(q qVar, p pVar) {
        this.a = 2;
        this.b = qVar;
        this.d = pVar;
        this.c = new io.reactivex.rxjava3.disposables.d(2);
    }

    public g(io.reactivex.rxjava3.core.b bVar, io.reactivex.rxjava3.core.a aVar) {
        this.a = 1;
        this.b = bVar;
        this.d = aVar;
        this.c = new io.reactivex.rxjava3.disposables.d(2);
    }
}
