package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class h extends io.reactivex.rxjava3.core.g implements io.reactivex.rxjava3.core.h {
    public static final g[] e = new g[0];
    public static final g[] f = new g[0];
    public Object c;
    public Throwable d;
    public final AtomicBoolean b = new AtomicBoolean();
    public final AtomicReference a = new AtomicReference(e);

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.a.get() == f) {
            bVar.dispose();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        g gVar = new g(hVar, this);
        hVar.a(gVar);
        while (true) {
            AtomicReference atomicReference = this.a;
            g[] gVarArr = (g[]) atomicReference.get();
            if (gVarArr == f) {
                Throwable th = this.d;
                if (th != null) {
                    hVar.onError(th);
                    return;
                }
                Object obj = this.c;
                if (obj == null) {
                    hVar.onComplete();
                    return;
                } else {
                    hVar.onSuccess(obj);
                    return;
                }
            }
            int length = gVarArr.length;
            g[] gVarArr2 = new g[length + 1];
            System.arraycopy(gVarArr, 0, gVarArr2, 0, length);
            gVarArr2[length] = gVar;
            while (!atomicReference.compareAndSet(gVarArr, gVarArr2)) {
                if (atomicReference.get() != gVarArr) {
                    break;
                }
            }
            if (gVar.get() == null) {
                i(gVar);
                return;
            }
            return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void i(g gVar) {
        g[] gVarArr;
        while (true) {
            AtomicReference atomicReference = this.a;
            g[] gVarArr2 = (g[]) atomicReference.get();
            int length = gVarArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (gVarArr2[i] == gVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                gVarArr = e;
            } else {
                g[] gVarArr3 = new g[length - 1];
                System.arraycopy(gVarArr2, 0, gVarArr3, 0, i);
                System.arraycopy(gVarArr2, i + 1, gVarArr3, i, (length - i) - 1);
                gVarArr = gVarArr3;
            }
            while (!atomicReference.compareAndSet(gVarArr2, gVarArr)) {
                if (atomicReference.get() != gVarArr2) {
                    break;
                }
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onComplete() {
        if (this.b.compareAndSet(false, true)) {
            for (g gVar : (g[]) this.a.getAndSet(f)) {
                gVar.a.onComplete();
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        if (!this.b.compareAndSet(false, true)) {
            C7.c(th);
            return;
        }
        this.d = th;
        for (g gVar : (g[]) this.a.getAndSet(f)) {
            gVar.a.onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onSuccess called with a null value.");
        if (this.b.compareAndSet(false, true)) {
            this.c = obj;
            for (g gVar : (g[]) this.a.getAndSet(f)) {
                gVar.a.onSuccess(obj);
            }
        }
    }
}
