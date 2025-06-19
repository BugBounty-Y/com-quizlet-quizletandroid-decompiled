package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class r extends io.reactivex.rxjava3.core.p implements io.reactivex.rxjava3.core.q {
    public static final q[] e = new q[0];
    public static final q[] f = new q[0];
    public Object c;
    public Throwable d;
    public final AtomicBoolean b = new AtomicBoolean();
    public final AtomicReference a = new AtomicReference(e);

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.a.get() == f) {
            bVar.dispose();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        q qVar2 = new q(qVar, this);
        qVar.a(qVar2);
        while (true) {
            AtomicReference atomicReference = this.a;
            q[] qVarArr = (q[]) atomicReference.get();
            if (qVarArr == f) {
                Throwable th = this.d;
                if (th != null) {
                    qVar.onError(th);
                    return;
                } else {
                    qVar.onSuccess(this.c);
                    return;
                }
            }
            int length = qVarArr.length;
            q[] qVarArr2 = new q[length + 1];
            System.arraycopy(qVarArr, 0, qVarArr2, 0, length);
            qVarArr2[length] = qVar2;
            while (!atomicReference.compareAndSet(qVarArr, qVarArr2)) {
                if (atomicReference.get() != qVarArr) {
                    break;
                }
            }
            if (qVar2.get() == null) {
                t(qVar2);
                return;
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        if (!this.b.compareAndSet(false, true)) {
            C7.c(th);
            return;
        }
        this.d = th;
        for (q qVar : (q[]) this.a.getAndSet(f)) {
            qVar.a.onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onSuccess called with a null value.");
        if (this.b.compareAndSet(false, true)) {
            this.c = obj;
            for (q qVar : (q[]) this.a.getAndSet(f)) {
                qVar.a.onSuccess(obj);
            }
        }
    }

    public final boolean r() {
        return this.a.get() == f && this.d != null;
    }

    public final boolean s() {
        return this.a.get() == f && this.c != null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void t(q qVar) {
        q[] qVarArr;
        while (true) {
            AtomicReference atomicReference = this.a;
            q[] qVarArr2 = (q[]) atomicReference.get();
            int length = qVarArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (qVarArr2[i] == qVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                qVarArr = e;
            } else {
                q[] qVarArr3 = new q[length - 1];
                System.arraycopy(qVarArr2, 0, qVarArr3, 0, i);
                System.arraycopy(qVarArr2, i + 1, qVarArr3, i, (length - i) - 1);
                qVarArr = qVarArr3;
            }
            while (!atomicReference.compareAndSet(qVarArr2, qVarArr)) {
                if (atomicReference.get() != qVarArr2) {
                    break;
                }
            }
            return;
        }
    }
}
