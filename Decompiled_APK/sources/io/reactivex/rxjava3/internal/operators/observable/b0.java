package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;

/* loaded from: classes3.dex */
public final class b0 extends io.reactivex.rxjava3.internal.observers.b implements io.reactivex.rxjava3.core.l, Runnable {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.core.n b;
    public final int c;
    public io.reactivex.rxjava3.operators.e d;
    public io.reactivex.rxjava3.disposables.b e;
    public Throwable f;
    public volatile boolean g;
    public volatile boolean h;
    public int i;
    public boolean j;

    public b0(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.core.n nVar, int i) {
        this.a = lVar;
        this.b = nVar;
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.e, bVar)) {
            this.e = bVar;
            if (bVar instanceof io.reactivex.rxjava3.operators.a) {
                io.reactivex.rxjava3.operators.a aVar = (io.reactivex.rxjava3.operators.a) bVar;
                int iH = aVar.h(7);
                if (iH == 1) {
                    this.i = iH;
                    this.d = aVar;
                    this.g = true;
                    this.a.a(this);
                    if (getAndIncrement() == 0) {
                        this.b.a(this);
                        return;
                    }
                    return;
                }
                if (iH == 2) {
                    this.i = iH;
                    this.d = aVar;
                    this.a.a(this);
                    return;
                }
            }
            this.d = new io.reactivex.rxjava3.operators.g(this.c);
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.g) {
            return;
        }
        if (this.i != 2) {
            this.d.offer(obj);
        }
        if (getAndIncrement() == 0) {
            this.b.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.d.clear();
    }

    public final boolean d(boolean z, boolean z2, io.reactivex.rxjava3.core.l lVar) {
        if (this.h) {
            this.d.clear();
            return true;
        }
        if (!z) {
            return false;
        }
        Throwable th = this.f;
        if (th != null) {
            this.h = true;
            this.d.clear();
            lVar.onError(th);
            this.b.dispose();
            return true;
        }
        if (!z2) {
            return false;
        }
        this.h = true;
        lVar.onComplete();
        this.b.dispose();
        return true;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.h) {
            return;
        }
        this.h = true;
        this.e.dispose();
        this.b.dispose();
        if (this.j || getAndIncrement() != 0) {
            return;
        }
        this.d.clear();
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        this.j = true;
        return 2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.d.isEmpty();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.g) {
            return;
        }
        this.g = true;
        if (getAndIncrement() == 0) {
            this.b.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.g) {
            C7.c(th);
            return;
        }
        this.f = th;
        this.g = true;
        if (getAndIncrement() == 0) {
            this.b.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        return this.d.poll();
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x0070, code lost:
    
        r3 = addAndGet(-r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0075, code lost:
    
        if (r3 != 0) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:?, code lost:
    
        return;
     */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            r7 = this;
            boolean r0 = r7.j
            r1 = 1
            if (r0 == 0) goto L4a
            r0 = r1
        L6:
            boolean r2 = r7.h
            if (r2 == 0) goto Lc
            goto L92
        Lc:
            boolean r2 = r7.g
            java.lang.Throwable r3 = r7.f
            if (r2 == 0) goto L23
            if (r3 == 0) goto L23
            r7.h = r1
            io.reactivex.rxjava3.core.l r0 = r7.a
            java.lang.Throwable r1 = r7.f
            r0.onError(r1)
            io.reactivex.rxjava3.core.n r0 = r7.b
            r0.dispose()
            return
        L23:
            io.reactivex.rxjava3.core.l r3 = r7.a
            r4 = 0
            r3.b(r4)
            if (r2 == 0) goto L42
            r7.h = r1
            java.lang.Throwable r0 = r7.f
            if (r0 == 0) goto L37
            io.reactivex.rxjava3.core.l r1 = r7.a
            r1.onError(r0)
            goto L3c
        L37:
            io.reactivex.rxjava3.core.l r0 = r7.a
            r0.onComplete()
        L3c:
            io.reactivex.rxjava3.core.n r0 = r7.b
            r0.dispose()
            return
        L42:
            int r0 = -r0
            int r0 = r7.addAndGet(r0)
            if (r0 != 0) goto L6
            goto L92
        L4a:
            io.reactivex.rxjava3.operators.e r0 = r7.d
            io.reactivex.rxjava3.core.l r2 = r7.a
            r3 = r1
        L4f:
            boolean r4 = r7.g
            boolean r5 = r0.isEmpty()
            boolean r4 = r7.d(r4, r5, r2)
            if (r4 == 0) goto L5c
            goto L92
        L5c:
            boolean r4 = r7.g
            java.lang.Object r5 = r0.poll()     // Catch: java.lang.Throwable -> L7c
            if (r5 != 0) goto L66
            r6 = r1
            goto L67
        L66:
            r6 = 0
        L67:
            boolean r4 = r7.d(r4, r6, r2)
            if (r4 == 0) goto L6e
            goto L92
        L6e:
            if (r6 == 0) goto L78
            int r3 = -r3
            int r3 = r7.addAndGet(r3)
            if (r3 != 0) goto L4f
            goto L92
        L78:
            r2.b(r5)
            goto L5c
        L7c:
            r3 = move-exception
            com.google.android.gms.internal.mlkit_vision_barcode.x7.b(r3)
            r7.h = r1
            io.reactivex.rxjava3.disposables.b r1 = r7.e
            r1.dispose()
            r0.clear()
            r2.onError(r3)
            io.reactivex.rxjava3.core.n r0 = r7.b
            r0.dispose()
        L92:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.observable.b0.run():void");
    }
}
