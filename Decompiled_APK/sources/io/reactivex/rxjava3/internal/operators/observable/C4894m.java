package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4894m extends AtomicReference implements io.reactivex.rxjava3.core.l {
    public final C4895n a;
    public final int b;

    public C4894m(C4895n c4895n, int i) {
        this.a = c4895n;
        this.b = i;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        boolean z;
        C4895n c4895n = this.a;
        int i = this.b;
        synchronized (c4895n) {
            try {
                Object[] objArr = c4895n.d;
                if (objArr == null) {
                    return;
                }
                Object obj2 = objArr[i];
                int i2 = c4895n.i;
                if (obj2 == null) {
                    i2++;
                    c4895n.i = i2;
                }
                objArr[i] = obj;
                if (i2 == objArr.length) {
                    c4895n.e.offer(objArr.clone());
                    z = true;
                } else {
                    z = false;
                }
                if (z) {
                    c4895n.c();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x001f A[Catch: all -> 0x000b, TryCatch #0 {all -> 0x000b, blocks: (B:4:0x0005, B:6:0x0009, B:10:0x000d, B:15:0x0017, B:18:0x0021, B:17:0x001f), top: B:25:0x0005 }] */
    @Override // io.reactivex.rxjava3.core.l
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onComplete() {
        /*
            r5 = this;
            io.reactivex.rxjava3.internal.operators.observable.n r0 = r5.a
            int r1 = r5.b
            monitor-enter(r0)
            java.lang.Object[] r2 = r0.d     // Catch: java.lang.Throwable -> Lb
            if (r2 != 0) goto Ld
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb
            return
        Lb:
            r1 = move-exception
            goto L2b
        Ld:
            r1 = r2[r1]     // Catch: java.lang.Throwable -> Lb
            r3 = 1
            if (r1 != 0) goto L14
            r1 = r3
            goto L15
        L14:
            r1 = 0
        L15:
            if (r1 != 0) goto L1f
            int r4 = r0.j     // Catch: java.lang.Throwable -> Lb
            int r4 = r4 + r3
            r0.j = r4     // Catch: java.lang.Throwable -> Lb
            int r2 = r2.length     // Catch: java.lang.Throwable -> Lb
            if (r4 != r2) goto L21
        L1f:
            r0.g = r3     // Catch: java.lang.Throwable -> Lb
        L21:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb
            if (r1 == 0) goto L27
            r0.a()
        L27:
            r0.c()
            return
        L2b:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Lb
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.observable.C4894m.onComplete():void");
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        C4895n c4895n = this.a;
        if (c4895n.h.c(th)) {
            c4895n.a();
            c4895n.c();
        }
    }
}
