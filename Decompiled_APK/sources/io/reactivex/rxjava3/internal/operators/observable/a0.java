package io.reactivex.rxjava3.internal.operators.observable;

import java.util.Collection;
import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class a0 implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public io.reactivex.rxjava3.disposables.b b;
    public final Object c;
    public Object d;

    public /* synthetic */ a0(Object obj, Collection collection, int i) {
        this.a = i;
        this.c = obj;
        this.d = collection;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((io.reactivex.rxjava3.core.q) this.c).a(this);
                    break;
                }
                break;
            case 1:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((io.reactivex.rxjava3.core.l) this.c).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((io.reactivex.rxjava3.core.q) this.c).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                this.d = obj;
                break;
            case 1:
                ((Collection) this.d).add(obj);
                break;
            default:
                ((Collection) this.d).add(obj);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.b.dispose();
                this.b = io.reactivex.rxjava3.internal.disposables.a.a;
                break;
            case 1:
                this.b.dispose();
                break;
            default:
                this.b.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                this.b = io.reactivex.rxjava3.internal.disposables.a.a;
                Object obj = this.d;
                io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.c;
                if (obj == null) {
                    qVar.onError(new NoSuchElementException());
                    break;
                } else {
                    this.d = null;
                    qVar.onSuccess(obj);
                    break;
                }
            case 1:
                Collection collection = (Collection) this.d;
                this.d = null;
                io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.c;
                lVar.b(collection);
                lVar.onComplete();
                break;
            default:
                Collection collection2 = (Collection) this.d;
                this.d = null;
                ((io.reactivex.rxjava3.core.q) this.c).onSuccess(collection2);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.b = io.reactivex.rxjava3.internal.disposables.a.a;
                this.d = null;
                ((io.reactivex.rxjava3.core.q) this.c).onError(th);
                break;
            case 1:
                this.d = null;
                ((io.reactivex.rxjava3.core.l) this.c).onError(th);
                break;
            default:
                this.d = null;
                ((io.reactivex.rxjava3.core.q) this.c).onError(th);
                break;
        }
    }

    public a0(io.reactivex.rxjava3.core.q qVar) {
        this.a = 0;
        this.c = qVar;
    }
}
