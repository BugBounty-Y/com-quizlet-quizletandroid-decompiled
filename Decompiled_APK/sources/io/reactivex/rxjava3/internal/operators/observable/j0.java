package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class j0 extends AtomicBoolean implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final C4896o b;
    public final i0 c;
    public io.reactivex.rxjava3.disposables.b d;

    public j0(io.reactivex.rxjava3.core.l lVar, C4896o c4896o, i0 i0Var) {
        this.a = lVar;
        this.b = c4896o;
        this.c = i0Var;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
            this.d = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        this.a.b(obj);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.d.dispose();
        if (compareAndSet(false, true)) {
            C4896o c4896o = this.b;
            i0 i0Var = this.c;
            synchronized (c4896o) {
                try {
                    i0 i0Var2 = (i0) c4896o.c;
                    if (i0Var2 != null && i0Var2 == i0Var) {
                        long j = i0Var.b - 1;
                        i0Var.b = j;
                        if (j == 0 && i0Var.c) {
                            c4896o.A(i0Var);
                        }
                    }
                } finally {
                }
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (compareAndSet(false, true)) {
            this.b.z(this.c);
            this.a.onComplete();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (!compareAndSet(false, true)) {
            C7.c(th);
        } else {
            this.b.z(this.c);
            this.a.onError(th);
        }
    }
}
