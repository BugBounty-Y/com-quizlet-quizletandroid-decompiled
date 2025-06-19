package io.reactivex.rxjava3.internal.operators.completable;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.internal.operators.observable.I;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class d extends AtomicReference implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.b {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public d(io.reactivex.rxjava3.core.b bVar) {
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
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
                    ((io.reactivex.rxjava3.core.b) this.b).onComplete();
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
                I i = (I) this.b;
                i.d.c(this);
                i.onComplete();
                return;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.disposables.b bVar;
        switch (this.a) {
            case 0:
                Object obj = get();
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (obj == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) == aVar) {
                    C7.c(th);
                    return;
                }
                try {
                    ((io.reactivex.rxjava3.core.b) this.b).onError(th);
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
                I i = (I) this.b;
                i.d.c(this);
                i.onError(th);
                return;
        }
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

    public d(I i) {
        this.b = i;
    }
}
