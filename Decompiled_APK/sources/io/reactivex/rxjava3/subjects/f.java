package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class f extends io.reactivex.rxjava3.core.a implements io.reactivex.rxjava3.core.b {
    public static final e[] d = new e[0];
    public static final e[] e = new e[0];
    public Throwable c;
    public final AtomicBoolean b = new AtomicBoolean();
    public final AtomicReference a = new AtomicReference(d);

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.a.get() == e) {
            bVar.dispose();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        e eVar = new e(bVar, this);
        bVar.a(eVar);
        while (true) {
            AtomicReference atomicReference = this.a;
            e[] eVarArr = (e[]) atomicReference.get();
            if (eVarArr == e) {
                Throwable th = this.c;
                if (th != null) {
                    bVar.onError(th);
                    return;
                } else {
                    bVar.onComplete();
                    return;
                }
            }
            int length = eVarArr.length;
            e[] eVarArr2 = new e[length + 1];
            System.arraycopy(eVarArr, 0, eVarArr2, 0, length);
            eVarArr2[length] = eVar;
            while (!atomicReference.compareAndSet(eVarArr, eVarArr2)) {
                if (atomicReference.get() != eVarArr) {
                    break;
                }
            }
            if (eVar.get() == null) {
                i(eVar);
                return;
            }
            return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void i(e eVar) {
        e[] eVarArr;
        while (true) {
            AtomicReference atomicReference = this.a;
            e[] eVarArr2 = (e[]) atomicReference.get();
            int length = eVarArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (eVarArr2[i] == eVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                eVarArr = d;
            } else {
                e[] eVarArr3 = new e[length - 1];
                System.arraycopy(eVarArr2, 0, eVarArr3, 0, i);
                System.arraycopy(eVarArr2, i + 1, eVarArr3, i, (length - i) - 1);
                eVarArr = eVarArr3;
            }
            while (!atomicReference.compareAndSet(eVarArr2, eVarArr)) {
                if (atomicReference.get() != eVarArr2) {
                    break;
                }
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        if (this.b.compareAndSet(false, true)) {
            for (e eVar : (e[]) this.a.getAndSet(e)) {
                eVar.a.onComplete();
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        if (!this.b.compareAndSet(false, true)) {
            C7.c(th);
            return;
        }
        this.c = th;
        for (e eVar : (e[]) this.a.getAndSet(e)) {
            eVar.a.onError(th);
        }
    }
}
