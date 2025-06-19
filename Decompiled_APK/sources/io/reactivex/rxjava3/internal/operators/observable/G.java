package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class G extends AtomicInteger implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.l {
    public static final F[] o = new F[0];
    public static final F[] p = new F[0];
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.h b;
    public final int c;
    public final int d;
    public volatile io.reactivex.rxjava3.operators.d e;
    public volatile boolean f;
    public final io.reactivex.rxjava3.internal.util.b g = new io.reactivex.rxjava3.internal.util.b();
    public volatile boolean h;
    public final AtomicReference i;
    public io.reactivex.rxjava3.disposables.b j;
    public long k;
    public int l;
    public final ArrayDeque m;
    public int n;

    public G(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar, int i, int i2) {
        this.a = lVar;
        this.b = hVar;
        this.c = i;
        this.d = i2;
        if (i != Integer.MAX_VALUE) {
            this.m = new ArrayDeque(i);
        }
        this.i = new AtomicReference(o);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.j, bVar)) {
            this.j = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.f) {
            return;
        }
        try {
            Object objApply = this.b.apply(obj);
            Objects.requireNonNull(objApply, "The mapper returned a null ObservableSource");
            io.reactivex.rxjava3.core.k kVar = (io.reactivex.rxjava3.core.k) objApply;
            if (this.c != Integer.MAX_VALUE) {
                synchronized (this) {
                    try {
                        int i = this.n;
                        if (i == this.c) {
                            this.m.offer(kVar);
                            return;
                        }
                        this.n = i + 1;
                    } finally {
                    }
                }
            }
            h(kVar);
        } catch (Throwable th) {
            x7.b(th);
            this.j.dispose();
            onError(th);
        }
    }

    public final boolean c() {
        if (this.h) {
            return true;
        }
        if (((Throwable) this.g.get()) == null) {
            return false;
        }
        d();
        this.g.g(this.a);
        return true;
    }

    public final boolean d() {
        this.j.dispose();
        AtomicReference atomicReference = this.i;
        F[] fArr = p;
        F[] fArr2 = (F[]) atomicReference.getAndSet(fArr);
        if (fArr2 == fArr) {
            return false;
        }
        for (F f : fArr2) {
            f.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(f);
        }
        return true;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.h = true;
        if (d()) {
            this.g.d();
        }
    }

    public final void e() {
        if (getAndIncrement() == 0) {
            f();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x00c7 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00c6 A[PHI: r4
  0x00c6: PHI (r4v6 int) = (r4v4 int), (r4v7 int) binds: [B:57:0x00ac, B:66:0x00c4] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f() {
        /*
            Method dump skipped, instructions count: 223
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.observable.G.f():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void g(F f) {
        F[] fArr;
        while (true) {
            AtomicReference atomicReference = this.i;
            F[] fArr2 = (F[]) atomicReference.get();
            int length = fArr2.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (fArr2[i] == f) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                fArr = o;
            } else {
                F[] fArr3 = new F[length - 1];
                System.arraycopy(fArr2, 0, fArr3, 0, i);
                System.arraycopy(fArr2, i + 1, fArr3, i, (length - i) - 1);
                fArr = fArr3;
            }
            while (!atomicReference.compareAndSet(fArr2, fArr)) {
                if (atomicReference.get() != fArr2) {
                    break;
                }
            }
            return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void h(io.reactivex.rxjava3.core.k kVar) {
        boolean z;
        do {
            z = false;
            if (!(kVar instanceof io.reactivex.rxjava3.functions.j)) {
                this.k++;
                F f = new F(this);
                while (true) {
                    AtomicReference atomicReference = this.i;
                    F[] fArr = (F[]) atomicReference.get();
                    if (fArr == p) {
                        io.reactivex.rxjava3.internal.disposables.a.a(f);
                        return;
                    }
                    int length = fArr.length;
                    F[] fArr2 = new F[length + 1];
                    System.arraycopy(fArr, 0, fArr2, 0, length);
                    fArr2[length] = f;
                    while (!atomicReference.compareAndSet(fArr, fArr2)) {
                        if (atomicReference.get() != fArr) {
                            break;
                        }
                    }
                    kVar.c(f);
                    return;
                }
            }
            try {
                Object obj = ((io.reactivex.rxjava3.functions.j) kVar).get();
                if (obj != null) {
                    if (get() == 0 && compareAndSet(0, 1)) {
                        this.a.b(obj);
                        if (decrementAndGet() != 0) {
                        }
                    } else {
                        io.reactivex.rxjava3.operators.d gVar = this.e;
                        if (gVar == null) {
                            gVar = this.c == Integer.MAX_VALUE ? new io.reactivex.rxjava3.operators.g(this.d) : new io.reactivex.rxjava3.operators.f(this.c);
                            this.e = gVar;
                        }
                        gVar.offer(obj);
                        if (getAndIncrement() != 0) {
                            return;
                        }
                    }
                    f();
                }
            } catch (Throwable th) {
                x7.b(th);
                this.g.c(th);
                e();
            }
            if (this.c == Integer.MAX_VALUE) {
                return;
            }
            synchronized (this) {
                try {
                    kVar = (io.reactivex.rxjava3.core.k) this.m.poll();
                    if (kVar == null) {
                        this.n--;
                        z = true;
                    }
                } catch (Throwable th2) {
                    throw th2;
                }
            }
        } while (!z);
        e();
    }

    public final void j(int i) {
        while (true) {
            int i2 = i - 1;
            if (i == 0) {
                return;
            }
            synchronized (this) {
                try {
                    io.reactivex.rxjava3.core.k kVar = (io.reactivex.rxjava3.core.k) this.m.poll();
                    if (kVar == null) {
                        this.n--;
                    } else {
                        h(kVar);
                    }
                } finally {
                }
            }
            i = i2;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.f) {
            return;
        }
        this.f = true;
        e();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.f) {
            C7.c(th);
        } else if (this.g.c(th)) {
            this.f = true;
            e();
        }
    }
}
