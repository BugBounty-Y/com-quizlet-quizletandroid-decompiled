package io.reactivex.rxjava3.internal.operators.maybe;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class q extends AtomicReference implements io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.disposables.b, Runnable, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.o b;
    public Object c;
    public Throwable d;
    public final Object e;

    public /* synthetic */ q(Object obj, io.reactivex.rxjava3.core.o oVar, int i) {
        this.a = i;
        this.e = obj;
        this.b = oVar;
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((io.reactivex.rxjava3.core.h) this.e).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((io.reactivex.rxjava3.core.q) this.e).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        io.reactivex.rxjava3.internal.disposables.a.c(this, this.b.b(this));
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.d = th;
                io.reactivex.rxjava3.internal.disposables.a.c(this, this.b.b(this));
                break;
            default:
                this.d = th;
                io.reactivex.rxjava3.internal.disposables.a.c(this, this.b.b(this));
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                this.c = obj;
                io.reactivex.rxjava3.internal.disposables.a.c(this, this.b.b(this));
                break;
            default:
                this.c = obj;
                io.reactivex.rxjava3.internal.disposables.a.c(this, this.b.b(this));
                break;
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Throwable th = this.d;
                io.reactivex.rxjava3.core.h hVar = (io.reactivex.rxjava3.core.h) this.e;
                if (th == null) {
                    Object obj = this.c;
                    if (obj == null) {
                        hVar.onComplete();
                        break;
                    } else {
                        this.c = null;
                        hVar.onSuccess(obj);
                        break;
                    }
                } else {
                    this.d = null;
                    hVar.onError(th);
                    break;
                }
            default:
                Throwable th2 = this.d;
                io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.e;
                if (th2 == null) {
                    qVar.onSuccess(this.c);
                    break;
                } else {
                    qVar.onError(th2);
                    break;
                }
        }
    }
}
