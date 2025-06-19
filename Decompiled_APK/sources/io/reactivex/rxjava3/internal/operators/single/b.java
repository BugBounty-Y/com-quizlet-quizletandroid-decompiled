package io.reactivex.rxjava3.internal.operators.single;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class b extends io.reactivex.rxjava3.core.p implements io.reactivex.rxjava3.core.q {
    public static final a[] f = new a[0];
    public static final a[] g = new a[0];
    public final io.reactivex.rxjava3.core.p a;
    public final AtomicInteger b = new AtomicInteger();
    public final AtomicReference c = new AtomicReference(f);
    public Object d;
    public Throwable e;

    public b(io.reactivex.rxjava3.core.p pVar) {
        this.a = pVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        a aVar = new a(qVar, this);
        qVar.a(aVar);
        while (true) {
            AtomicReference atomicReference = this.c;
            a[] aVarArr = (a[]) atomicReference.get();
            if (aVarArr == g) {
                Throwable th = this.e;
                if (th != null) {
                    qVar.onError(th);
                    return;
                } else {
                    qVar.onSuccess(this.d);
                    return;
                }
            }
            int length = aVarArr.length;
            a[] aVarArr2 = new a[length + 1];
            System.arraycopy(aVarArr, 0, aVarArr2, 0, length);
            aVarArr2[length] = aVar;
            while (!atomicReference.compareAndSet(aVarArr, aVarArr2)) {
                if (atomicReference.get() != aVarArr) {
                    break;
                }
            }
            if (aVar.get()) {
                r(aVar);
            }
            if (this.b.getAndIncrement() == 0) {
                this.a.j(this);
                return;
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.e = th;
        for (a aVar : (a[]) this.c.getAndSet(g)) {
            if (!aVar.get()) {
                aVar.a.onError(th);
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        this.d = obj;
        for (a aVar : (a[]) this.c.getAndSet(g)) {
            if (!aVar.get()) {
                aVar.a.onSuccess(obj);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void r(a aVar) {
        a[] aVarArr;
        while (true) {
            AtomicReference atomicReference = this.c;
            a[] aVarArr2 = (a[]) atomicReference.get();
            int length = aVarArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (aVarArr2[i] == aVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                aVarArr = f;
            } else {
                a[] aVarArr3 = new a[length - 1];
                System.arraycopy(aVarArr2, 0, aVarArr3, 0, i);
                System.arraycopy(aVarArr2, i + 1, aVarArr3, i, (length - i) - 1);
                aVarArr = aVarArr3;
            }
            while (!atomicReference.compareAndSet(aVarArr2, aVarArr)) {
                if (atomicReference.get() != aVarArr2) {
                    break;
                }
            }
            return;
        }
    }
}
