package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class j extends s {
    public static final i[] c = new i[0];
    public static final i[] d = new i[0];
    public final AtomicReference a = new AtomicReference(d);
    public Throwable b;

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.a.get() == c) {
            bVar.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onNext called with a null value.");
        for (i iVar : (i[]) this.a.get()) {
            if (!iVar.get()) {
                iVar.a.b(obj);
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        AtomicReference atomicReference = this.a;
        Object obj = atomicReference.get();
        Object obj2 = c;
        if (obj == obj2) {
            return;
        }
        i[] iVarArr = (i[]) atomicReference.getAndSet(obj2);
        for (i iVar : iVarArr) {
            if (!iVar.get()) {
                iVar.a.onComplete();
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        AtomicReference atomicReference = this.a;
        Object obj = atomicReference.get();
        Object obj2 = c;
        if (obj == obj2) {
            C7.c(th);
            return;
        }
        this.b = th;
        i[] iVarArr = (i[]) atomicReference.getAndSet(obj2);
        for (i iVar : iVarArr) {
            if (iVar.get()) {
                C7.c(th);
            } else {
                iVar.a.onError(th);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        i iVar = new i(lVar, this);
        lVar.a(iVar);
        while (true) {
            AtomicReference atomicReference = this.a;
            i[] iVarArr = (i[]) atomicReference.get();
            if (iVarArr == c) {
                Throwable th = this.b;
                if (th != null) {
                    lVar.onError(th);
                    return;
                } else {
                    lVar.onComplete();
                    return;
                }
            }
            int length = iVarArr.length;
            i[] iVarArr2 = new i[length + 1];
            System.arraycopy(iVarArr, 0, iVarArr2, 0, length);
            iVarArr2[length] = iVar;
            while (!atomicReference.compareAndSet(iVarArr, iVarArr2)) {
                if (atomicReference.get() != iVarArr) {
                    break;
                }
            }
            if (iVar.get()) {
                z(iVar);
                return;
            }
            return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void z(i iVar) {
        i[] iVarArr;
        while (true) {
            AtomicReference atomicReference = this.a;
            i[] iVarArr2 = (i[]) atomicReference.get();
            if (iVarArr2 == c || iVarArr2 == (iVarArr = d)) {
                return;
            }
            int length = iVarArr2.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (iVarArr2[i] == iVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length != 1) {
                iVarArr = new i[length - 1];
                System.arraycopy(iVarArr2, 0, iVarArr, 0, i);
                System.arraycopy(iVarArr2, i + 1, iVarArr, i, (length - i) - 1);
            }
            while (!atomicReference.compareAndSet(iVarArr2, iVarArr)) {
                if (atomicReference.get() != iVarArr2) {
                    break;
                }
            }
            return;
        }
    }
}
