package io.reactivex.rxjava3.internal.operators.single;

import androidx.compose.ui.node.B;
import io.reactivex.rxjava3.internal.operators.observable.O;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class c extends AtomicReference implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public c(io.reactivex.rxjava3.core.q qVar) {
        this.b = qVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    public boolean b(Throwable th) {
        io.reactivex.rxjava3.disposables.b bVar;
        if (th == null) {
            th = io.reactivex.rxjava3.internal.util.c.a("onError called with a null Throwable.");
        }
        Object obj = get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (obj == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) == aVar) {
            return false;
        }
        try {
            ((io.reactivex.rxjava3.core.q) this.b).onError(th);
        } finally {
            if (bVar != null) {
                bVar.dispose();
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        O o = (O) this.b;
        io.reactivex.rxjava3.disposables.a aVar = o.b;
        aVar.c(this);
        if (o.d.c(th)) {
            o.g.dispose();
            aVar.dispose();
            o.c.decrementAndGet();
            if (o.getAndIncrement() == 0) {
                o.c();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x004b  */
    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onSuccess(java.lang.Object r5) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L8c;
                default: goto L5;
            }
        L5:
            java.lang.Object r0 = r4.b
            io.reactivex.rxjava3.internal.operators.observable.O r0 = (io.reactivex.rxjava3.internal.operators.observable.O) r0
            io.reactivex.rxjava3.disposables.a r1 = r0.b
            r1.c(r4)
            int r1 = r0.get()
            if (r1 != 0) goto L4b
            r1 = 0
            r2 = 1
            boolean r3 = r0.compareAndSet(r1, r2)
            if (r3 == 0) goto L4b
            io.reactivex.rxjava3.core.l r3 = r0.a
            r3.b(r5)
            java.util.concurrent.atomic.AtomicInteger r5 = r0.c
            int r5 = r5.decrementAndGet()
            if (r5 != 0) goto L2a
            r1 = r2
        L2a:
            java.util.concurrent.atomic.AtomicReference r5 = r0.f
            java.lang.Object r5 = r5.get()
            io.reactivex.rxjava3.operators.g r5 = (io.reactivex.rxjava3.operators.g) r5
            if (r1 == 0) goto L44
            if (r5 == 0) goto L3c
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L44
        L3c:
            io.reactivex.rxjava3.internal.util.b r5 = r0.d
            io.reactivex.rxjava3.core.l r0 = r0.a
            r5.g(r0)
            goto L88
        L44:
            int r5 = r0.decrementAndGet()
            if (r5 != 0) goto L85
            goto L88
        L4b:
            java.util.concurrent.atomic.AtomicReference r1 = r0.f
            java.lang.Object r2 = r1.get()
            io.reactivex.rxjava3.operators.g r2 = (io.reactivex.rxjava3.operators.g) r2
            if (r2 == 0) goto L57
        L55:
            r3 = r2
            goto L74
        L57:
            io.reactivex.rxjava3.operators.g r2 = new io.reactivex.rxjava3.operators.g
            int r3 = io.reactivex.rxjava3.core.e.a
            r2.<init>(r3)
        L5e:
            r3 = 0
            boolean r3 = r1.compareAndSet(r3, r2)
            if (r3 == 0) goto L66
            goto L55
        L66:
            java.lang.Object r3 = r1.get()
            if (r3 == 0) goto L5e
            java.lang.Object r1 = r1.get()
            r2 = r1
            io.reactivex.rxjava3.operators.g r2 = (io.reactivex.rxjava3.operators.g) r2
            goto L55
        L74:
            monitor-enter(r3)
            r3.offer(r5)     // Catch: java.lang.Throwable -> L89
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L89
            java.util.concurrent.atomic.AtomicInteger r5 = r0.c
            r5.decrementAndGet()
            int r5 = r0.getAndIncrement()
            if (r5 == 0) goto L85
            goto L88
        L85:
            r0.c()
        L88:
            return
        L89:
            r5 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L89
            throw r5
        L8c:
            java.lang.Object r0 = r4.get()
            io.reactivex.rxjava3.internal.disposables.a r1 = io.reactivex.rxjava3.internal.disposables.a.a
            if (r0 == r1) goto Lbd
            java.lang.Object r0 = r4.getAndSet(r1)
            io.reactivex.rxjava3.disposables.b r0 = (io.reactivex.rxjava3.disposables.b) r0
            if (r0 == r1) goto Lbd
            java.lang.Object r1 = r4.b
            io.reactivex.rxjava3.core.q r1 = (io.reactivex.rxjava3.core.q) r1
            if (r5 != 0) goto Lae
            java.lang.String r5 = "onSuccess called with a null value."
            java.lang.NullPointerException r5 = io.reactivex.rxjava3.internal.util.c.a(r5)     // Catch: java.lang.Throwable -> Lac
            r1.onError(r5)     // Catch: java.lang.Throwable -> Lac
            goto Lb1
        Lac:
            r5 = move-exception
            goto Lb7
        Lae:
            r1.onSuccess(r5)     // Catch: java.lang.Throwable -> Lac
        Lb1:
            if (r0 == 0) goto Lbd
            r0.dispose()
            goto Lbd
        Lb7:
            if (r0 == 0) goto Lbc
            r0.dispose()
        Lbc:
            throw r5
        Lbd:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.single.c.onSuccess(java.lang.Object):void");
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public String toString() {
        switch (this.a) {
            case 0:
                return B.i(c.class.getSimpleName(), "{", super.toString(), "}");
            default:
                return super.toString();
        }
    }

    public c(O o) {
        this.b = o;
    }
}
