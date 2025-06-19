package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4893l extends AbstractC4882a implements io.reactivex.rxjava3.core.l {
    public static final C4892k[] j = new C4892k[0];
    public static final C4892k[] k = new C4892k[0];
    public final AtomicBoolean b;
    public final AtomicReference c;
    public volatile long d;
    public final com.bumptech.glide.load.engine.k e;
    public com.bumptech.glide.load.engine.k f;
    public int g;
    public Throwable h;
    public volatile boolean i;

    public C4893l(C4884c c4884c) {
        super(c4884c);
        this.b = new AtomicBoolean();
        com.bumptech.glide.load.engine.k kVar = new com.bumptech.glide.load.engine.k(16);
        this.e = kVar;
        this.f = kVar;
        this.c = new AtomicReference(j);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        int i = this.g;
        if (i == 16) {
            com.bumptech.glide.load.engine.k kVar = new com.bumptech.glide.load.engine.k(i);
            ((Object[]) kVar.b)[0] = obj;
            this.g = 1;
            this.f.a = kVar;
            this.f = kVar;
        } else {
            ((Object[]) this.f.b)[i] = obj;
            this.g = i + 1;
        }
        this.d++;
        for (C4892k c4892k : (C4892k[]) this.c.get()) {
            z(c4892k);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.i = true;
        for (C4892k c4892k : (C4892k[]) this.c.getAndSet(k)) {
            z(c4892k);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.h = th;
        this.i = true;
        for (C4892k c4892k : (C4892k[]) this.c.getAndSet(k)) {
            z(c4892k);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        C4892k c4892k = new C4892k(lVar, this);
        lVar.a(c4892k);
        loop0: while (true) {
            AtomicReference atomicReference = this.c;
            C4892k[] c4892kArr = (C4892k[]) atomicReference.get();
            if (c4892kArr != k) {
                int length = c4892kArr.length;
                C4892k[] c4892kArr2 = new C4892k[length + 1];
                System.arraycopy(c4892kArr, 0, c4892kArr2, 0, length);
                c4892kArr2[length] = c4892k;
                while (!atomicReference.compareAndSet(c4892kArr, c4892kArr2)) {
                    if (atomicReference.get() != c4892kArr) {
                        break;
                    }
                }
                break loop0;
            }
            break;
        }
        AtomicBoolean atomicBoolean = this.b;
        if (atomicBoolean.get() || !atomicBoolean.compareAndSet(false, true)) {
            z(c4892k);
        } else {
            this.a.c(this);
        }
    }

    public final void z(C4892k c4892k) {
        if (c4892k.getAndIncrement() != 0) {
            return;
        }
        long j2 = c4892k.e;
        int i = c4892k.d;
        com.bumptech.glide.load.engine.k kVar = c4892k.c;
        io.reactivex.rxjava3.core.l lVar = c4892k.a;
        int iAddAndGet = 1;
        while (!c4892k.f) {
            boolean z = this.i;
            boolean z2 = this.d == j2;
            if (z && z2) {
                c4892k.c = null;
                Throwable th = this.h;
                if (th != null) {
                    lVar.onError(th);
                    return;
                } else {
                    lVar.onComplete();
                    return;
                }
            }
            if (z2) {
                c4892k.e = j2;
                c4892k.d = i;
                c4892k.c = kVar;
                iAddAndGet = c4892k.addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            } else {
                if (i == 16) {
                    kVar = (com.bumptech.glide.load.engine.k) kVar.a;
                    i = 0;
                }
                lVar.b(((Object[]) kVar.b)[i]);
                i++;
                j2++;
            }
        }
        c4892k.c = null;
    }
}
