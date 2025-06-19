package io.reactivex.rxjava3.internal.operators.maybe;

import androidx.compose.ui.node.B;
import io.reactivex.rxjava3.internal.operators.observable.K;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class d extends AtomicReference implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.b {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public d(io.reactivex.rxjava3.core.h hVar) {
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    public void b(Object obj) {
        io.reactivex.rxjava3.disposables.b bVar;
        Object obj2 = get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (obj2 == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) == aVar) {
            return;
        }
        try {
            ((io.reactivex.rxjava3.core.h) this.b).onSuccess(obj);
        } finally {
            if (bVar != null) {
                bVar.dispose();
            }
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

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        io.reactivex.rxjava3.disposables.b bVar;
        switch (this.a) {
            case 0:
                Object obj = get();
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (obj == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) == aVar) {
                    return;
                }
                try {
                    ((io.reactivex.rxjava3.core.h) this.b).onComplete();
                    if (bVar != null) {
                        return;
                    } else {
                        return;
                    }
                } finally {
                    if (bVar != null) {
                        bVar.dispose();
                    }
                }
            default:
                K k = (K) this.b;
                k.d.c(this);
                k.onComplete();
                return;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        K k = (K) this.b;
        k.d.c(this);
        k.onError(th);
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public String toString() {
        switch (this.a) {
            case 0:
                return B.i(d.class.getSimpleName(), "{", super.toString(), "}");
            default:
                return super.toString();
        }
    }

    public d(K k) {
        this.b = k;
    }
}
