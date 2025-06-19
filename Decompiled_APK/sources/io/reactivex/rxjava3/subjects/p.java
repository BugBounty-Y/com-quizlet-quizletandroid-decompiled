package io.reactivex.rxjava3.subjects;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class p extends s {
    public static final m[] d = new m[0];
    public static final m[] e = new m[0];
    public static final Object[] f = new Object[0];
    public final AtomicReference a;
    public final AtomicReference b = new AtomicReference(d);
    public boolean c;

    /* JADX WARN: Multi-variable type inference failed */
    public p(l lVar) {
        this.a = (AtomicReference) lVar;
    }

    public static p z() {
        return new p(new o());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void A(m mVar) {
        m[] mVarArr;
        while (true) {
            AtomicReference atomicReference = this.b;
            m[] mVarArr2 = (m[]) atomicReference.get();
            if (mVarArr2 == e || mVarArr2 == (mVarArr = d)) {
                return;
            }
            int length = mVarArr2.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (mVarArr2[i] == mVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length != 1) {
                mVarArr = new m[length - 1];
                System.arraycopy(mVarArr2, 0, mVarArr, 0, i);
                System.arraycopy(mVarArr2, i + 1, mVarArr, i, (length - i) - 1);
            }
            while (!atomicReference.compareAndSet(mVarArr2, mVarArr)) {
                if (atomicReference.get() != mVarArr2) {
                    break;
                }
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.c) {
            bVar.dispose();
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [io.reactivex.rxjava3.subjects.l, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onNext called with a null value.");
        if (this.c) {
            return;
        }
        ?? r0 = this.a;
        r0.add(obj);
        for (m mVar : (m[]) this.b.get()) {
            r0.a(mVar);
        }
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [io.reactivex.rxjava3.subjects.l, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.c) {
            return;
        }
        this.c = true;
        io.reactivex.rxjava3.internal.util.e eVar = io.reactivex.rxjava3.internal.util.e.a;
        ?? r1 = this.a;
        r1.b(eVar);
        r1.compareAndSet(null, eVar);
        for (m mVar : (m[]) this.b.getAndSet(e)) {
            r1.a(mVar);
        }
    }

    /* JADX WARN: Type inference failed for: r5v1, types: [io.reactivex.rxjava3.subjects.l, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        if (this.c) {
            C7.c(th);
            return;
        }
        this.c = true;
        io.reactivex.rxjava3.internal.util.d dVar = new io.reactivex.rxjava3.internal.util.d(th);
        ?? r5 = this.a;
        r5.b(dVar);
        r5.compareAndSet(null, dVar);
        for (m mVar : (m[]) this.b.getAndSet(e)) {
            r5.a(mVar);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v2, types: [io.reactivex.rxjava3.subjects.l, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        m mVar = new m(lVar, this);
        lVar.a(mVar);
        while (true) {
            AtomicReference atomicReference = this.b;
            m[] mVarArr = (m[]) atomicReference.get();
            if (mVarArr == e) {
                break;
            }
            int length = mVarArr.length;
            m[] mVarArr2 = new m[length + 1];
            System.arraycopy(mVarArr, 0, mVarArr2, 0, length);
            mVarArr2[length] = mVar;
            while (!atomicReference.compareAndSet(mVarArr, mVarArr2)) {
                if (atomicReference.get() != mVarArr) {
                    break;
                }
            }
            if (mVar.d) {
                A(mVar);
                return;
            }
        }
        this.a.a(mVar);
    }
}
