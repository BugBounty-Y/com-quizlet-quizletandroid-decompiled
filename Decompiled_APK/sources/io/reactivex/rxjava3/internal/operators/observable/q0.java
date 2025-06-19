package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class q0 extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public static final p0 j;
    public final io.reactivex.rxjava3.core.l a;
    public final com.quizlet.data.repository.searchexplanations.c b;
    public final int c;
    public volatile boolean e;
    public volatile boolean f;
    public io.reactivex.rxjava3.disposables.b g;
    public volatile long i;
    public final AtomicReference h = new AtomicReference();
    public final io.reactivex.rxjava3.internal.util.b d = new io.reactivex.rxjava3.internal.util.b();

    static {
        p0 p0Var = new p0(null, -1L, 1);
        j = p0Var;
        io.reactivex.rxjava3.internal.disposables.a.a(p0Var);
    }

    public q0(io.reactivex.rxjava3.core.l lVar, com.quizlet.data.repository.searchexplanations.c cVar, int i) {
        this.a = lVar;
        this.b = cVar;
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.g, bVar)) {
            this.g = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        long j2 = this.i + 1;
        this.i = j2;
        p0 p0Var = (p0) this.h.get();
        if (p0Var != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(p0Var);
        }
        try {
            Object objApply = this.b.apply(obj);
            Objects.requireNonNull(objApply, "The ObservableSource returned is null");
            io.reactivex.rxjava3.core.k kVar = (io.reactivex.rxjava3.core.k) objApply;
            p0 p0Var2 = new p0(this, j2, this.c);
            while (true) {
                p0 p0Var3 = (p0) this.h.get();
                if (p0Var3 == j) {
                    return;
                }
                AtomicReference atomicReference = this.h;
                while (!atomicReference.compareAndSet(p0Var3, p0Var2)) {
                    if (atomicReference.get() != p0Var3) {
                        break;
                    }
                }
                kVar.c(p0Var2);
                return;
            }
        } catch (Throwable th) {
            x7.b(th);
            this.g.dispose();
            onError(th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:78:0x00ba A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x000e A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c() {
        /*
            r12 = this;
            int r0 = r12.getAndIncrement()
            if (r0 == 0) goto L8
            goto Lc1
        L8:
            io.reactivex.rxjava3.core.l r0 = r12.a
            java.util.concurrent.atomic.AtomicReference r1 = r12.h
            r2 = 1
            r3 = r2
        Le:
            boolean r4 = r12.f
            if (r4 == 0) goto L14
            goto Lc1
        L14:
            boolean r4 = r12.e
            r5 = 0
            if (r4 == 0) goto L38
            java.lang.Object r4 = r1.get()
            if (r4 != 0) goto L21
            r4 = r2
            goto L22
        L21:
            r4 = r5
        L22:
            io.reactivex.rxjava3.internal.util.b r6 = r12.d
            java.lang.Object r6 = r6.get()
            java.lang.Throwable r6 = (java.lang.Throwable) r6
            if (r6 == 0) goto L32
            io.reactivex.rxjava3.internal.util.b r1 = r12.d
            r1.g(r0)
            return
        L32:
            if (r4 == 0) goto L38
            r0.onComplete()
            return
        L38:
            java.lang.Object r4 = r1.get()
            io.reactivex.rxjava3.internal.operators.observable.p0 r4 = (io.reactivex.rxjava3.internal.operators.observable.p0) r4
            if (r4 == 0) goto Lba
            io.reactivex.rxjava3.operators.e r6 = r4.d
            if (r6 == 0) goto Lba
            r7 = r5
        L45:
            boolean r8 = r12.f
            if (r8 == 0) goto L4b
            goto Lc1
        L4b:
            java.lang.Object r8 = r1.get()
            if (r4 == r8) goto L53
        L51:
            r7 = r2
            goto Lb2
        L53:
            io.reactivex.rxjava3.internal.util.b r8 = r12.d
            java.lang.Object r8 = r8.get()
            java.lang.Throwable r8 = (java.lang.Throwable) r8
            if (r8 == 0) goto L63
            io.reactivex.rxjava3.internal.util.b r1 = r12.d
            r1.g(r0)
            return
        L63:
            boolean r8 = r4.e
            r9 = 0
            java.lang.Object r10 = r6.poll()     // Catch: java.lang.Throwable -> L6b
            goto L99
        L6b:
            r7 = move-exception
            com.google.android.gms.internal.mlkit_vision_barcode.x7.b(r7)
            io.reactivex.rxjava3.internal.util.b r10 = r12.d
            r10.c(r7)
        L74:
            boolean r7 = r1.compareAndSet(r4, r9)
            if (r7 == 0) goto L7b
            goto L81
        L7b:
            java.lang.Object r7 = r1.get()
            if (r7 == r4) goto L74
        L81:
            java.util.concurrent.atomic.AtomicReference r7 = r12.h
            io.reactivex.rxjava3.internal.operators.observable.p0 r10 = io.reactivex.rxjava3.internal.operators.observable.q0.j
            java.lang.Object r7 = r7.getAndSet(r10)
            io.reactivex.rxjava3.internal.operators.observable.p0 r7 = (io.reactivex.rxjava3.internal.operators.observable.p0) r7
            if (r7 == 0) goto L90
            io.reactivex.rxjava3.internal.disposables.a.a(r7)
        L90:
            io.reactivex.rxjava3.disposables.b r7 = r12.g
            r7.dispose()
            r12.e = r2
            r7 = r2
            r10 = r9
        L99:
            if (r10 != 0) goto L9d
            r11 = r2
            goto L9e
        L9d:
            r11 = r5
        L9e:
            if (r8 == 0) goto Lb0
            if (r11 == 0) goto Lb0
        La2:
            boolean r5 = r1.compareAndSet(r4, r9)
            if (r5 == 0) goto La9
            goto Laf
        La9:
            java.lang.Object r5 = r1.get()
            if (r5 == r4) goto La2
        Laf:
            goto L51
        Lb0:
            if (r11 == 0) goto Lb6
        Lb2:
            if (r7 == 0) goto Lba
            goto Le
        Lb6:
            r0.b(r10)
            goto L45
        Lba:
            int r3 = -r3
            int r3 = r12.addAndGet(r3)
            if (r3 != 0) goto Le
        Lc1:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: io.reactivex.rxjava3.internal.operators.observable.q0.c():void");
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.f) {
            return;
        }
        this.f = true;
        this.g.dispose();
        p0 p0Var = (p0) this.h.getAndSet(j);
        if (p0Var != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(p0Var);
        }
        this.d.d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.e) {
            return;
        }
        this.e = true;
        c();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.e || !this.d.b(th)) {
            C7.c(th);
            return;
        }
        p0 p0Var = (p0) this.h.getAndSet(j);
        if (p0Var != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(p0Var);
        }
        this.e = true;
        c();
    }
}
