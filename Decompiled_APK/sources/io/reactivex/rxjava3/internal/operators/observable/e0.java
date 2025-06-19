package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class e0 extends AtomicReference implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public static final d0[] e = new d0[0];
    public static final d0[] f = new d0[0];
    public final AtomicReference b;
    public Throwable d;
    public final AtomicBoolean a = new AtomicBoolean();
    public final AtomicReference c = new AtomicReference();

    public e0(AtomicReference atomicReference) {
        this.b = atomicReference;
        lazySet(e);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this.c, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        for (d0 d0Var : (d0[]) get()) {
            d0Var.a.b(obj);
        }
    }

    public final boolean c() {
        return get() == f;
    }

    public final void d(d0 d0Var) {
        d0[] d0VarArr;
        d0[] d0VarArr2;
        do {
            d0VarArr = (d0[]) get();
            int length = d0VarArr.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (d0VarArr[i] == d0Var) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            d0VarArr2 = e;
            if (length != 1) {
                d0VarArr2 = new d0[length - 1];
                System.arraycopy(d0VarArr, 0, d0VarArr2, 0, i);
                System.arraycopy(d0VarArr, i + 1, d0VarArr2, i, (length - i) - 1);
            }
        } while (!compareAndSet(d0VarArr, d0VarArr2));
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        AtomicReference atomicReference;
        getAndSet(f);
        do {
            atomicReference = this.b;
            if (atomicReference.compareAndSet(this, null)) {
                break;
            }
        } while (atomicReference.get() == this);
        io.reactivex.rxjava3.internal.disposables.a.a(this.c);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.c.lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
        for (d0 d0Var : (d0[]) getAndSet(f)) {
            d0Var.a.onComplete();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        AtomicReference atomicReference = this.c;
        Object obj = atomicReference.get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (obj == aVar) {
            C7.c(th);
            return;
        }
        this.d = th;
        atomicReference.lazySet(aVar);
        for (d0 d0Var : (d0[]) getAndSet(f)) {
            d0Var.a.onError(th);
        }
    }
}
