package io.reactivex.rxjava3.subjects;

import androidx.appcompat.widget.C0122z;
import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* loaded from: classes3.dex */
public final class d extends s {
    public static final c[] g = new c[0];
    public static final c[] h = new c[0];
    public final AtomicReference a;
    public final AtomicReference b;
    public final Lock c;
    public final Lock d;
    public final AtomicReference e;
    public long f;

    public d(Object obj) {
        ReentrantReadWriteLock reentrantReadWriteLock = new ReentrantReadWriteLock();
        this.c = reentrantReadWriteLock.readLock();
        this.d = reentrantReadWriteLock.writeLock();
        this.b = new AtomicReference(g);
        this.a = new AtomicReference(obj);
        this.e = new AtomicReference();
    }

    public static d z() {
        return new d(null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void A(c cVar) {
        c[] cVarArr;
        while (true) {
            AtomicReference atomicReference = this.b;
            c[] cVarArr2 = (c[]) atomicReference.get();
            int length = cVarArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (cVarArr2[i] == cVar) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                cVarArr = g;
            } else {
                c[] cVarArr3 = new c[length - 1];
                System.arraycopy(cVarArr2, 0, cVarArr3, 0, i);
                System.arraycopy(cVarArr2, i + 1, cVarArr3, i, (length - i) - 1);
                cVarArr = cVarArr3;
            }
            while (!atomicReference.compareAndSet(cVarArr2, cVarArr)) {
                if (atomicReference.get() != cVarArr2) {
                    break;
                }
            }
            return;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.e.get() != null) {
            bVar.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.internal.util.c.b(obj, "onNext called with a null value.");
        if (this.e.get() != null) {
            return;
        }
        Lock lock = this.d;
        lock.lock();
        this.f++;
        this.a.lazySet(obj);
        lock.unlock();
        for (c cVar : (c[]) this.b.get()) {
            cVar.a(this.f, obj);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        AtomicReference atomicReference = this.e;
        C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
        while (!atomicReference.compareAndSet(null, c2245jv)) {
            if (atomicReference.get() != null) {
                return;
            }
        }
        io.reactivex.rxjava3.internal.util.e eVar = io.reactivex.rxjava3.internal.util.e.a;
        Lock lock = this.d;
        lock.lock();
        this.f++;
        this.a.lazySet(eVar);
        lock.unlock();
        for (c cVar : (c[]) this.b.getAndSet(h)) {
            cVar.a(this.f, eVar);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.internal.util.c.b(th, "onError called with a null Throwable.");
        AtomicReference atomicReference = this.e;
        while (!atomicReference.compareAndSet(null, th)) {
            if (atomicReference.get() != null) {
                C7.c(th);
                return;
            }
        }
        io.reactivex.rxjava3.internal.util.d dVar = new io.reactivex.rxjava3.internal.util.d(th);
        Lock lock = this.d;
        lock.lock();
        this.f++;
        this.a.lazySet(dVar);
        lock.unlock();
        for (c cVar : (c[]) this.b.getAndSet(h)) {
            cVar.a(this.f, dVar);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        C0122z c0122z;
        Object obj;
        c cVar = new c(lVar, this);
        lVar.a(cVar);
        while (true) {
            AtomicReference atomicReference = this.b;
            c[] cVarArr = (c[]) atomicReference.get();
            if (cVarArr == h) {
                Throwable th = (Throwable) this.e.get();
                if (th == io.reactivex.rxjava3.internal.util.c.a) {
                    lVar.onComplete();
                    return;
                } else {
                    lVar.onError(th);
                    return;
                }
            }
            int length = cVarArr.length;
            c[] cVarArr2 = new c[length + 1];
            System.arraycopy(cVarArr, 0, cVarArr2, 0, length);
            cVarArr2[length] = cVar;
            while (!atomicReference.compareAndSet(cVarArr, cVarArr2)) {
                if (atomicReference.get() != cVarArr) {
                    break;
                }
            }
            if (cVar.g) {
                A(cVar);
                return;
            }
            if (cVar.g) {
                return;
            }
            synchronized (cVar) {
                try {
                    if (cVar.g) {
                        return;
                    }
                    if (cVar.c) {
                        return;
                    }
                    d dVar = cVar.b;
                    Lock lock = dVar.c;
                    lock.lock();
                    cVar.h = dVar.f;
                    Object obj2 = dVar.a.get();
                    lock.unlock();
                    cVar.d = obj2 != null;
                    cVar.c = true;
                    if (obj2 == null || cVar.test(obj2)) {
                        return;
                    }
                    while (!cVar.g) {
                        synchronized (cVar) {
                            try {
                                c0122z = cVar.e;
                                if (c0122z == null) {
                                    cVar.d = false;
                                    return;
                                }
                                cVar.e = null;
                            } finally {
                            }
                        }
                        for (Object[] objArr = (Object[]) c0122z.c; objArr != null; objArr = objArr[4]) {
                            for (int i = 0; i < 4 && (obj = objArr[i]) != null; i++) {
                                if (cVar.test(obj)) {
                                    break;
                                }
                            }
                        }
                    }
                    return;
                } finally {
                }
            }
        }
    }
}
