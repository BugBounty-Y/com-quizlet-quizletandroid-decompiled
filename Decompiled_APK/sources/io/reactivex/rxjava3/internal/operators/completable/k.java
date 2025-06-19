package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.core.q;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class k extends AtomicReference implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.core.f, q {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public void b(Object obj) {
        if (io.reactivex.rxjava3.internal.subscriptions.c.a(this)) {
            ((io.reactivex.rxjava3.internal.observers.e) this.b).c(new CancellationException());
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public void c(org.reactivestreams.b bVar) {
        if (io.reactivex.rxjava3.internal.subscriptions.c.b(this, bVar)) {
            bVar.e(Long.MAX_VALUE);
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        switch (this.a) {
            case 0:
                l lVar = (l) this.b;
                if (((AtomicBoolean) lVar.d).compareAndSet(false, true)) {
                    io.reactivex.rxjava3.internal.disposables.a.a(lVar);
                    ((io.reactivex.rxjava3.core.b) lVar.b).onComplete();
                    break;
                }
                break;
            default:
                Object obj = get();
                io.reactivex.rxjava3.internal.subscriptions.c cVar = io.reactivex.rxjava3.internal.subscriptions.c.a;
                if (obj != cVar) {
                    lazySet(cVar);
                    ((io.reactivex.rxjava3.internal.observers.e) this.b).c(new CancellationException());
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                l lVar = (l) this.b;
                if (!((AtomicBoolean) lVar.d).compareAndSet(false, true)) {
                    C7.c(th);
                    break;
                } else {
                    io.reactivex.rxjava3.internal.disposables.a.a(lVar);
                    ((io.reactivex.rxjava3.core.b) lVar.b).onError(th);
                    break;
                }
            case 1:
                ((io.reactivex.rxjava3.internal.observers.e) this.b).c(th);
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
}
