package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class b extends s {
    public static final a[] d = new a[0];
    public static final a[] e = new a[0];
    public final AtomicReference a = new AtomicReference(d);
    public Throwable b;
    public Object c;

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.a.get() == e) {
            bVar.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onNext called with a null value.");
        if (this.a.get() == e) {
            return;
        }
        this.c = obj;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        AtomicReference atomicReference = this.a;
        Object obj = atomicReference.get();
        Object obj2 = e;
        if (obj == obj2) {
            return;
        }
        Object obj3 = this.c;
        a[] aVarArr = (a[]) atomicReference.getAndSet(obj2);
        int i = 0;
        if (obj3 != null) {
            int length = aVarArr.length;
            while (i < length) {
                aVarArr[i].d(obj3);
                i++;
            }
            return;
        }
        int length2 = aVarArr.length;
        while (i < length2) {
            a aVar = aVarArr[i];
            if (!aVar.e()) {
                aVar.a.onComplete();
            }
            i++;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        AtomicReference atomicReference = this.a;
        Object obj = atomicReference.get();
        Object obj2 = e;
        if (obj == obj2) {
            C7.c(th);
            return;
        }
        this.c = null;
        this.b = th;
        a[] aVarArr = (a[]) atomicReference.getAndSet(obj2);
        for (a aVar : aVarArr) {
            if (aVar.e()) {
                C7.c(th);
            } else {
                aVar.a.onError(th);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        a aVar = new a(lVar, this);
        lVar.a(aVar);
        while (true) {
            AtomicReference atomicReference = this.a;
            a[] aVarArr = (a[]) atomicReference.get();
            if (aVarArr != e) {
                int length = aVarArr.length;
                a[] aVarArr2 = new a[length + 1];
                System.arraycopy(aVarArr, 0, aVarArr2, 0, length);
                aVarArr2[length] = aVar;
                while (!atomicReference.compareAndSet(aVarArr, aVarArr2)) {
                    if (atomicReference.get() != aVarArr) {
                        break;
                    }
                }
                if (aVar.e()) {
                    z(aVar);
                    return;
                }
                return;
            }
            Throwable th = this.b;
            if (th != null) {
                lVar.onError(th);
                return;
            }
            Object obj = this.c;
            if (obj != null) {
                aVar.d(obj);
                return;
            } else {
                if (aVar.e()) {
                    return;
                }
                aVar.a.onComplete();
                return;
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void z(a aVar) {
        a[] aVarArr;
        while (true) {
            AtomicReference atomicReference = this.a;
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
                aVarArr = d;
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
