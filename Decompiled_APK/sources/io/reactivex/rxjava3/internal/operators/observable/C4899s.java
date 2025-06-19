package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4899s extends AtomicReference implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a = 0;
    public final io.reactivex.rxjava3.core.l b;

    public C4899s(io.reactivex.rxjava3.core.l lVar) {
        this.b = lVar;
    }

    @Override // io.reactivex.rxjava3.core.h
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    public boolean b() {
        return io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get());
    }

    public void c(Object obj) {
        if (obj != null) {
            if (b()) {
                return;
            }
            this.b.b(obj);
        } else {
            NullPointerException nullPointerExceptionA = io.reactivex.rxjava3.internal.util.c.a("onNext called with a null value.");
            if (e(nullPointerExceptionA)) {
                return;
            }
            C7.c(nullPointerExceptionA);
        }
    }

    public void d(io.reactivex.rxjava3.functions.c cVar) {
        io.reactivex.rxjava3.internal.disposables.a.d(this, new io.reactivex.rxjava3.disposables.d(cVar, 1));
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

    public boolean e(Throwable th) {
        if (b()) {
            return false;
        }
        try {
            this.b.onError(th);
            io.reactivex.rxjava3.internal.disposables.a.a(this);
            return true;
        } catch (Throwable th2) {
            io.reactivex.rxjava3.internal.disposables.a.a(this);
            throw th2;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onComplete() {
        switch (this.a) {
            case 0:
                if (b()) {
                    return;
                }
                try {
                    this.b.onComplete();
                    return;
                } finally {
                    io.reactivex.rxjava3.internal.disposables.a.a(this);
                }
            default:
                M m = (M) this.b;
                m.c.c(this);
                int i = m.get();
                AtomicInteger atomicInteger = m.d;
                if (i == 0) {
                    if (m.compareAndSet(0, 1)) {
                        boolean z = atomicInteger.decrementAndGet() == 0;
                        io.reactivex.rxjava3.operators.g gVar = (io.reactivex.rxjava3.operators.g) m.g.get();
                        if (z && (gVar == null || gVar.isEmpty())) {
                            m.e.g(m.a);
                            return;
                        } else {
                            if (m.decrementAndGet() == 0) {
                                return;
                            }
                            m.c();
                            return;
                        }
                    }
                }
                atomicInteger.decrementAndGet();
                if (m.getAndIncrement() == 0) {
                    m.c();
                    return;
                }
                return;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onError(Throwable th) {
        M m = (M) this.b;
        io.reactivex.rxjava3.disposables.a aVar = m.c;
        aVar.c(this);
        if (m.e.c(th)) {
            if (!m.b) {
                m.h.dispose();
                aVar.dispose();
            }
            m.d.decrementAndGet();
            if (m.getAndIncrement() == 0) {
                m.c();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0046  */
    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onSuccess(java.lang.Object r5) {
        /*
            r4 = this;
            io.reactivex.rxjava3.core.l r0 = r4.b
            io.reactivex.rxjava3.internal.operators.observable.M r0 = (io.reactivex.rxjava3.internal.operators.observable.M) r0
            io.reactivex.rxjava3.disposables.a r1 = r0.c
            r1.c(r4)
            int r1 = r0.get()
            if (r1 != 0) goto L46
            r1 = 0
            r2 = 1
            boolean r3 = r0.compareAndSet(r1, r2)
            if (r3 == 0) goto L46
            io.reactivex.rxjava3.core.l r3 = r0.a
            r3.b(r5)
            java.util.concurrent.atomic.AtomicInteger r5 = r0.d
            int r5 = r5.decrementAndGet()
            if (r5 != 0) goto L25
            r1 = r2
        L25:
            java.util.concurrent.atomic.AtomicReference r5 = r0.g
            java.lang.Object r5 = r5.get()
            io.reactivex.rxjava3.operators.g r5 = (io.reactivex.rxjava3.operators.g) r5
            if (r1 == 0) goto L3f
            if (r5 == 0) goto L37
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3f
        L37:
            io.reactivex.rxjava3.internal.util.b r5 = r0.e
            io.reactivex.rxjava3.core.l r0 = r0.a
            r5.g(r0)
            return
        L3f:
            int r5 = r0.decrementAndGet()
            if (r5 != 0) goto L80
            goto L7f
        L46:
            java.util.concurrent.atomic.AtomicReference r1 = r0.g
            java.lang.Object r2 = r1.get()
            io.reactivex.rxjava3.operators.g r2 = (io.reactivex.rxjava3.operators.g) r2
            if (r2 == 0) goto L52
        L50:
            r3 = r2
            goto L6f
        L52:
            io.reactivex.rxjava3.operators.g r2 = new io.reactivex.rxjava3.operators.g
            int r3 = io.reactivex.rxjava3.core.e.a
            r2.<init>(r3)
        L59:
            r3 = 0
            boolean r3 = r1.compareAndSet(r3, r2)
            if (r3 == 0) goto L61
            goto L50
        L61:
            java.lang.Object r3 = r1.get()
            if (r3 == 0) goto L59
            java.lang.Object r1 = r1.get()
            r2 = r1
            io.reactivex.rxjava3.operators.g r2 = (io.reactivex.rxjava3.operators.g) r2
            goto L50
        L6f:
            monitor-enter(r3)
            r3.offer(r5)     // Catch: java.lang.Throwable -> L84
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L84
            java.util.concurrent.atomic.AtomicInteger r5 = r0.d
            r5.decrementAndGet()
            int r5 = r0.getAndIncrement()
            if (r5 == 0) goto L80
        L7f:
            return
        L80:
            r0.c()
            return
        L84:
            r5 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L84
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.observable.C4899s.onSuccess(java.lang.Object):void");
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public String toString() {
        switch (this.a) {
            case 0:
                return androidx.compose.ui.node.B.i(C4899s.class.getSimpleName(), "{", super.toString(), "}");
            default:
                return super.toString();
        }
    }

    public C4899s(M m) {
        this.b = m;
    }
}
