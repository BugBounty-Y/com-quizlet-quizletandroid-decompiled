package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.concurrent.locks.LockSupport;
import kotlin.collections.C4927s;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class Y extends Z implements J {
    public static final /* synthetic */ AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(Y.class, Object.class, "_queue$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater g = AtomicReferenceFieldUpdater.newUpdater(Y.class, Object.class, "_delayed$volatile");
    public static final /* synthetic */ AtomicIntegerFieldUpdater h = AtomicIntegerFieldUpdater.newUpdater(Y.class, "_isCompleted$volatile");
    private volatile /* synthetic */ Object _delayed$volatile;
    private volatile /* synthetic */ int _isCompleted$volatile;
    private volatile /* synthetic */ Object _queue$volatile;

    @Override // kotlinx.coroutines.J
    public final void f(long j, C5028l c5028l) {
        long j2 = j > 0 ? j >= 9223372036854L ? Long.MAX_VALUE : 1000000 * j : 0L;
        if (j2 < 4611686018427387903L) {
            long jNanoTime = System.nanoTime();
            U u = new U(this, j2 + jNanoTime, c5028l);
            v0(jNanoTime, u);
            c5028l.v(new C5022i(u, 2));
        }
    }

    public Q i(long j, Runnable runnable, CoroutineContext coroutineContext) {
        return G.a.i(j, runnable, coroutineContext);
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x0018, code lost:
    
        r7 = null;
     */
    @Override // kotlinx.coroutines.Z
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long o0() {
        /*
            r10 = this;
            boolean r0 = r10.p0()
            r1 = 0
            if (r0 == 0) goto La
            goto Lb1
        La:
            r10.s0()
        Ld:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = kotlinx.coroutines.Y.f
            java.lang.Object r3 = r0.get(r10)
            com.android.billingclient.api.a r4 = kotlinx.coroutines.E.c
            r5 = 0
            if (r3 != 0) goto L1a
        L18:
            r7 = r5
            goto L4a
        L1a:
            boolean r6 = r3 instanceof kotlinx.coroutines.internal.l
            if (r6 == 0) goto L3e
            r6 = r3
            kotlinx.coroutines.internal.l r6 = (kotlinx.coroutines.internal.l) r6
            java.lang.Object r7 = r6.d()
            com.android.billingclient.api.a r8 = kotlinx.coroutines.internal.l.g
            if (r7 == r8) goto L2c
            java.lang.Runnable r7 = (java.lang.Runnable) r7
            goto L4a
        L2c:
            kotlinx.coroutines.internal.l r6 = r6.c()
        L30:
            boolean r4 = r0.compareAndSet(r10, r3, r6)
            if (r4 == 0) goto L37
            goto Ld
        L37:
            java.lang.Object r4 = r0.get(r10)
            if (r4 == r3) goto L30
            goto Ld
        L3e:
            if (r3 != r4) goto L41
            goto L18
        L41:
            boolean r6 = r0.compareAndSet(r10, r3, r5)
            if (r6 == 0) goto Lb7
            r7 = r3
            java.lang.Runnable r7 = (java.lang.Runnable) r7
        L4a:
            if (r7 == 0) goto L50
            r7.run()
            return r1
        L50:
            kotlin.collections.s r3 = r10.d
            r6 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            if (r3 != 0) goto L5b
        L59:
            r8 = r6
            goto L63
        L5b:
            boolean r3 = r3.isEmpty()
            if (r3 == 0) goto L62
            goto L59
        L62:
            r8 = r1
        L63:
            int r3 = (r8 > r1 ? 1 : (r8 == r1 ? 0 : -1))
            if (r3 != 0) goto L68
            goto Lb1
        L68:
            java.lang.Object r0 = r0.get(r10)
            if (r0 == 0) goto L90
            boolean r3 = r0 instanceof kotlinx.coroutines.internal.l
            if (r3 == 0) goto L8d
            kotlinx.coroutines.internal.l r0 = (kotlinx.coroutines.internal.l) r0
            java.util.concurrent.atomic.AtomicLongFieldUpdater r3 = kotlinx.coroutines.internal.l.f
            long r3 = r3.get(r0)
            r8 = 1073741823(0x3fffffff, double:5.304989472E-315)
            long r8 = r8 & r3
            int r0 = (int) r8
            r8 = 1152921503533105152(0xfffffffc0000000, double:1.2882296003504729E-231)
            long r3 = r3 & r8
            r8 = 30
            long r3 = r3 >> r8
            int r3 = (int) r3
            if (r0 != r3) goto L8c
            goto L90
        L8c:
            return r1
        L8d:
            if (r0 != r4) goto Lb1
            goto Lb6
        L90:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = kotlinx.coroutines.Y.g
            java.lang.Object r0 = r0.get(r10)
            kotlinx.coroutines.X r0 = (kotlinx.coroutines.X) r0
            if (r0 == 0) goto Lb6
            monitor-enter(r0)
            kotlinx.coroutines.W[] r3 = r0.a     // Catch: java.lang.Throwable -> Lb3
            if (r3 == 0) goto La2
            r4 = 0
            r5 = r3[r4]     // Catch: java.lang.Throwable -> Lb3
        La2:
            monitor-exit(r0)
            if (r5 != 0) goto La6
            goto Lb6
        La6:
            long r3 = r5.a
            long r5 = java.lang.System.nanoTime()
            long r3 = r3 - r5
            int r0 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r0 >= 0) goto Lb2
        Lb1:
            return r1
        Lb2:
            return r3
        Lb3:
            r1 = move-exception
            monitor-exit(r0)
            throw r1
        Lb6:
            return r6
        Lb7:
            java.lang.Object r6 = r0.get(r10)
            if (r6 == r3) goto L41
            goto Ld
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.Y.o0():long");
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        r0(runnable);
    }

    public void r0(Runnable runnable) {
        s0();
        if (!t0(runnable)) {
            F.i.r0(runnable);
            return;
        }
        Thread threadM0 = m0();
        if (Thread.currentThread() != threadM0) {
            LockSupport.unpark(threadM0);
        }
    }

    public final void s0() {
        W wB;
        X x = (X) g.get(this);
        if (x == null || kotlinx.coroutines.internal.u.b.get(x) == 0) {
            return;
        }
        long jNanoTime = System.nanoTime();
        do {
            synchronized (x) {
                try {
                    W[] wArr = x.a;
                    W w = wArr != null ? wArr[0] : null;
                    if (w != null) {
                        wB = ((jNanoTime - w.a) > 0L ? 1 : ((jNanoTime - w.a) == 0L ? 0 : -1)) >= 0 ? t0(w) : false ? x.b(0) : null;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        } while (wB != null);
    }

    @Override // kotlinx.coroutines.Z
    public void shutdown() {
        W wB;
        C0.a.set(null);
        h.set(this, 1);
        loop0: while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
            Object obj = atomicReferenceFieldUpdater.get(this);
            C1472a c1472a = E.c;
            if (obj != null) {
                if (!(obj instanceof kotlinx.coroutines.internal.l)) {
                    if (obj != c1472a) {
                        kotlinx.coroutines.internal.l lVar = new kotlinx.coroutines.internal.l(8, true);
                        lVar.a((Runnable) obj);
                        while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, lVar)) {
                            if (atomicReferenceFieldUpdater.get(this) != obj) {
                                break;
                            }
                        }
                        break loop0;
                    }
                    break;
                }
                ((kotlinx.coroutines.internal.l) obj).b();
                break;
            }
            while (!atomicReferenceFieldUpdater.compareAndSet(this, null, c1472a)) {
                if (atomicReferenceFieldUpdater.get(this) != null) {
                    break;
                }
            }
            break loop0;
        }
        while (o0() <= 0) {
        }
        long jNanoTime = System.nanoTime();
        while (true) {
            X x = (X) g.get(this);
            if (x == null) {
                return;
            }
            synchronized (x) {
                wB = kotlinx.coroutines.internal.u.b.get(x) > 0 ? x.b(0) : null;
            }
            if (wB == null) {
                return;
            } else {
                q0(jNanoTime, wB);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0050, code lost:
    
        return false;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean t0(java.lang.Runnable r7) {
        /*
            r6 = this;
        L0:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = kotlinx.coroutines.Y.f
            java.lang.Object r1 = r0.get(r6)
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r2 = kotlinx.coroutines.Y.h
            int r2 = r2.get(r6)
            r3 = 0
            r4 = 1
            if (r2 != r4) goto L12
            r2 = r4
            goto L13
        L12:
            r2 = r3
        L13:
            if (r2 == 0) goto L16
            goto L50
        L16:
            if (r1 != 0) goto L27
        L18:
            r1 = 0
            boolean r1 = r0.compareAndSet(r6, r1, r7)
            if (r1 == 0) goto L20
            goto L67
        L20:
            java.lang.Object r1 = r0.get(r6)
            if (r1 == 0) goto L18
            goto L0
        L27:
            boolean r2 = r1 instanceof kotlinx.coroutines.internal.l
            if (r2 == 0) goto L4c
            r2 = r1
            kotlinx.coroutines.internal.l r2 = (kotlinx.coroutines.internal.l) r2
            int r5 = r2.a(r7)
            if (r5 == 0) goto L67
            if (r5 == r4) goto L3a
            r0 = 2
            if (r5 == r0) goto L50
            goto L0
        L3a:
            kotlinx.coroutines.internal.l r2 = r2.c()
        L3e:
            boolean r3 = r0.compareAndSet(r6, r1, r2)
            if (r3 == 0) goto L45
            goto L0
        L45:
            java.lang.Object r3 = r0.get(r6)
            if (r3 == r1) goto L3e
            goto L0
        L4c:
            com.android.billingclient.api.a r2 = kotlinx.coroutines.E.c
            if (r1 != r2) goto L51
        L50:
            return r3
        L51:
            kotlinx.coroutines.internal.l r2 = new kotlinx.coroutines.internal.l
            r3 = 8
            r2.<init>(r3, r4)
            r3 = r1
            java.lang.Runnable r3 = (java.lang.Runnable) r3
            r2.a(r3)
            r2.a(r7)
        L61:
            boolean r3 = r0.compareAndSet(r6, r1, r2)
            if (r3 == 0) goto L68
        L67:
            return r4
        L68:
            java.lang.Object r3 = r0.get(r6)
            if (r3 == r1) goto L61
            goto L0
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.Y.t0(java.lang.Runnable):boolean");
    }

    public final boolean u0() {
        X x;
        C4927s c4927s = this.d;
        if (!(c4927s != null ? c4927s.isEmpty() : true) || ((x = (X) g.get(this)) != null && kotlinx.coroutines.internal.u.b.get(x) != 0)) {
            return false;
        }
        Object obj = f.get(this);
        if (obj != null) {
            if (obj instanceof kotlinx.coroutines.internal.l) {
                long j = kotlinx.coroutines.internal.l.f.get((kotlinx.coroutines.internal.l) obj);
                return ((int) (1073741823 & j)) == ((int) ((j & 1152921503533105152L) >> 30));
            }
            if (obj != E.c) {
                return false;
            }
        }
        return true;
    }

    public final void v0(long j, W w) {
        int iA;
        Thread threadM0;
        boolean z = h.get(this) == 1;
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
        if (z) {
            iA = 1;
        } else {
            X x = (X) atomicReferenceFieldUpdater.get(this);
            if (x == null) {
                X x2 = new X();
                x2.c = j;
                while (!atomicReferenceFieldUpdater.compareAndSet(this, null, x2) && atomicReferenceFieldUpdater.get(this) == null) {
                }
                Object obj = atomicReferenceFieldUpdater.get(this);
                Intrinsics.d(obj);
                x = (X) obj;
            }
            iA = w.a(j, x, this);
        }
        if (iA != 0) {
            if (iA == 1) {
                q0(j, w);
                return;
            } else {
                if (iA != 2) {
                    throw new IllegalStateException("unexpected result");
                }
                return;
            }
        }
        X x3 = (X) atomicReferenceFieldUpdater.get(this);
        if (x3 != null) {
            synchronized (x3) {
                W[] wArr = x3.a;
                w = wArr != null ? wArr[0] : null;
            }
        }
        if (w != w || Thread.currentThread() == (threadM0 = m0())) {
            return;
        }
        LockSupport.unpark(threadM0);
    }
}
