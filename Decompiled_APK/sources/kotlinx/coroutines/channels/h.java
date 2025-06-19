package kotlinx.coroutines.channels;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.glance.appwidget.protobuf.Z;
import com.android.billingclient.api.C1472a;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5026k;
import kotlinx.coroutines.J0;

/* loaded from: classes3.dex */
public class h implements l {
    public static final /* synthetic */ AtomicLongFieldUpdater b = AtomicLongFieldUpdater.newUpdater(h.class, "sendersAndCloseStatus$volatile");
    public static final /* synthetic */ AtomicLongFieldUpdater c = AtomicLongFieldUpdater.newUpdater(h.class, "receivers$volatile");
    public static final /* synthetic */ AtomicLongFieldUpdater d = AtomicLongFieldUpdater.newUpdater(h.class, "bufferEnd$volatile");
    public static final /* synthetic */ AtomicLongFieldUpdater e = AtomicLongFieldUpdater.newUpdater(h.class, "completedExpandBuffersAndPauseFlag$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "sendSegment$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater g = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "receiveSegment$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater h = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "bufferEndSegment$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater i = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "_closeCause$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater j = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "closeHandler$volatile");
    private volatile /* synthetic */ Object _closeCause$volatile;
    public final int a;
    private volatile /* synthetic */ long bufferEnd$volatile;
    private volatile /* synthetic */ Object bufferEndSegment$volatile;
    private volatile /* synthetic */ Object closeHandler$volatile;
    private volatile /* synthetic */ long completedExpandBuffersAndPauseFlag$volatile;
    private volatile /* synthetic */ Object receiveSegment$volatile;
    private volatile /* synthetic */ long receivers$volatile;
    private volatile /* synthetic */ Object sendSegment$volatile;
    private volatile /* synthetic */ long sendersAndCloseStatus$volatile;

    public h(int i2) {
        this.a = i2;
        if (i2 < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i2, "Invalid channel capacity: ", ", should be >=0").toString());
        }
        p pVar = j.a;
        this.bufferEnd$volatile = i2 != 0 ? i2 != Integer.MAX_VALUE ? i2 : Long.MAX_VALUE : 0L;
        this.completedExpandBuffersAndPauseFlag$volatile = d.get(this);
        p pVar2 = new p(0L, null, this, 3);
        this.sendSegment$volatile = pVar2;
        this.receiveSegment$volatile = pVar2;
        if (B()) {
            pVar2 = j.a;
            Intrinsics.e(pVar2, "null cannot be cast to non-null type kotlinx.coroutines.channels.ChannelSegment<E of kotlinx.coroutines.channels.BufferedChannel>");
        }
        this.bufferEndSegment$volatile = pVar2;
        this._closeCause$volatile = j.s;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object E(kotlinx.coroutines.channels.h r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            boolean r0 = r14 instanceof kotlinx.coroutines.channels.f
            if (r0 == 0) goto L14
            r0 = r14
            kotlinx.coroutines.channels.f r0 = (kotlinx.coroutines.channels.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            kotlinx.coroutines.channels.f r0 = new kotlinx.coroutines.channels.f
            r0.<init>(r13, r14)
            goto L12
        L1a:
            java.lang.Object r14 = r6.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r2 = 1
            if (r1 == 0) goto L35
            if (r1 != r2) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r14)
            kotlinx.coroutines.channels.o r14 = (kotlinx.coroutines.channels.o) r14
            java.lang.Object r13 = r14.a
            return r13
        L2d:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r14 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r14)
            throw r13
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r14 = kotlinx.coroutines.channels.h.g
            java.lang.Object r14 = r14.get(r13)
            kotlinx.coroutines.channels.p r14 = (kotlinx.coroutines.channels.p) r14
        L40:
            boolean r1 = r13.y()
            if (r1 == 0) goto L50
            java.lang.Throwable r13 = r13.r()
            kotlinx.coroutines.channels.m r14 = new kotlinx.coroutines.channels.m
            r14.<init>(r13)
            return r14
        L50:
            java.util.concurrent.atomic.AtomicLongFieldUpdater r1 = kotlinx.coroutines.channels.h.c
            long r4 = r1.getAndIncrement(r13)
            int r1 = kotlinx.coroutines.channels.j.b
            long r7 = (long) r1
            long r9 = r4 / r7
            long r7 = r4 % r7
            int r3 = (int) r7
            long r7 = r14.c
            int r1 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r1 == 0) goto L6d
            kotlinx.coroutines.channels.p r1 = r13.q(r9, r14)
            if (r1 != 0) goto L6b
            goto L40
        L6b:
            r8 = r1
            goto L6e
        L6d:
            r8 = r14
        L6e:
            r12 = 0
            r7 = r13
            r9 = r3
            r10 = r4
            java.lang.Object r13 = r7.J(r8, r9, r10, r12)
            r1 = r7
            com.android.billingclient.api.a r14 = kotlinx.coroutines.channels.j.m
            if (r13 == r14) goto La0
            com.android.billingclient.api.a r14 = kotlinx.coroutines.channels.j.o
            if (r13 != r14) goto L8d
            long r13 = r1.v()
            int r13 = (r4 > r13 ? 1 : (r4 == r13 ? 0 : -1))
            if (r13 >= 0) goto L8a
            r8.a()
        L8a:
            r13 = r1
            r14 = r8
            goto L40
        L8d:
            com.android.billingclient.api.a r14 = kotlinx.coroutines.channels.j.n
            if (r13 != r14) goto L9c
            r6.l = r2
            r2 = r8
            java.lang.Object r13 = r1.F(r2, r3, r4, r6)
            if (r13 != r0) goto L9b
            return r0
        L9b:
            return r13
        L9c:
            r8.a()
            return r13
        La0:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r14 = "unexpected"
            r13.<init>(r14)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.E(kotlinx.coroutines.channels.h, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final p a(h hVar, long j2, p pVar) {
        Object objB;
        h hVar2;
        hVar.getClass();
        p pVar2 = j.a;
        i iVar = i.a;
        loop0: while (true) {
            objB = kotlinx.coroutines.internal.b.b(pVar, j2, iVar);
            if (!kotlinx.coroutines.internal.b.e(objB)) {
                kotlinx.coroutines.internal.q qVarC = kotlinx.coroutines.internal.b.c(objB);
                while (true) {
                    AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
                    kotlinx.coroutines.internal.q qVar = (kotlinx.coroutines.internal.q) atomicReferenceFieldUpdater.get(hVar);
                    if (qVar.c >= qVarC.c) {
                        break loop0;
                    }
                    if (!qVarC.j()) {
                        break;
                    }
                    while (!atomicReferenceFieldUpdater.compareAndSet(hVar, qVar, qVarC)) {
                        if (atomicReferenceFieldUpdater.get(hVar) != qVar) {
                            if (qVarC.f()) {
                                qVarC.e();
                            }
                        }
                    }
                    if (qVar.f()) {
                        qVar.e();
                    }
                }
            } else {
                break;
            }
        }
        boolean zE = kotlinx.coroutines.internal.b.e(objB);
        AtomicLongFieldUpdater atomicLongFieldUpdater = c;
        if (zE) {
            hVar.z();
            if (pVar.c * j.b < atomicLongFieldUpdater.get(hVar)) {
                pVar.a();
                return null;
            }
        } else {
            p pVar3 = (p) kotlinx.coroutines.internal.b.c(objB);
            long j3 = pVar3.c;
            if (j3 <= j2) {
                return pVar3;
            }
            long j4 = j.b * j3;
            while (true) {
                AtomicLongFieldUpdater atomicLongFieldUpdater2 = b;
                long j5 = atomicLongFieldUpdater2.get(hVar);
                long j6 = 1152921504606846975L & j5;
                if (j6 >= j4) {
                    hVar2 = hVar;
                    break;
                }
                hVar2 = hVar;
                if (atomicLongFieldUpdater2.compareAndSet(hVar2, j5, j6 + (((int) (j5 >> 60)) << 60))) {
                    break;
                }
                hVar = hVar2;
            }
            if (j3 * j.b < atomicLongFieldUpdater.get(hVar2)) {
                pVar3.a();
            }
        }
        return null;
    }

    public static final void b(h hVar, Object obj, C5028l c5028l) {
        hVar.getClass();
        Throwable thU = hVar.u();
        kotlin.p pVar = kotlin.r.b;
        c5028l.resumeWith(Z.b(thU));
    }

    public static final int d(h hVar, p pVar, int i2, Object obj, long j2, Object obj2, boolean z) {
        hVar.getClass();
        pVar.n(i2, obj);
        if (z) {
            return hVar.K(pVar, i2, obj, j2, obj2, z);
        }
        Object objL = pVar.l(i2);
        if (objL == null) {
            if (hVar.f(j2)) {
                if (pVar.k(i2, null, j.d)) {
                    return 1;
                }
            } else {
                if (obj2 == null) {
                    return 3;
                }
                if (pVar.k(i2, null, obj2)) {
                    return 2;
                }
            }
        } else if (objL instanceof J0) {
            pVar.n(i2, null);
            if (hVar.H(objL, obj)) {
                pVar.o(i2, j.i);
                return 0;
            }
            C1472a c1472a = j.k;
            if (pVar.f.getAndSet((i2 * 2) + 1, c1472a) == c1472a) {
                return 5;
            }
            pVar.m(i2, true);
            return 5;
        }
        return hVar.K(pVar, i2, obj, j2, obj2, z);
    }

    public static void w(h hVar) {
        hVar.getClass();
        AtomicLongFieldUpdater atomicLongFieldUpdater = e;
        if ((atomicLongFieldUpdater.addAndGet(hVar, 1L) & 4611686018427387904L) != 0) {
            while ((atomicLongFieldUpdater.get(hVar) & 4611686018427387904L) != 0) {
            }
        }
    }

    public boolean A() {
        return false;
    }

    public final boolean B() {
        long j2 = d.get(this);
        return j2 == 0 || j2 == Long.MAX_VALUE;
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x0011, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void C(long r5, kotlinx.coroutines.channels.p r7) {
        /*
            r4 = this;
        L0:
            long r0 = r7.c
            int r0 = (r0 > r5 ? 1 : (r0 == r5 ? 0 : -1))
            if (r0 >= 0) goto L11
            kotlinx.coroutines.internal.c r0 = r7.c()
            kotlinx.coroutines.channels.p r0 = (kotlinx.coroutines.channels.p) r0
            if (r0 != 0) goto Lf
            goto L11
        Lf:
            r7 = r0
            goto L0
        L11:
            boolean r5 = r7.d()
            if (r5 == 0) goto L22
            kotlinx.coroutines.internal.c r5 = r7.c()
            kotlinx.coroutines.channels.p r5 = (kotlinx.coroutines.channels.p) r5
            if (r5 != 0) goto L20
            goto L22
        L20:
            r7 = r5
            goto L11
        L22:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r5 = kotlinx.coroutines.channels.h.h
            java.lang.Object r6 = r5.get(r4)
            kotlinx.coroutines.internal.q r6 = (kotlinx.coroutines.internal.q) r6
            long r0 = r6.c
            long r2 = r7.c
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 < 0) goto L33
            goto L49
        L33:
            boolean r0 = r7.j()
            if (r0 != 0) goto L3a
            goto L11
        L3a:
            boolean r0 = r5.compareAndSet(r4, r6, r7)
            if (r0 == 0) goto L4a
            boolean r5 = r6.f()
            if (r5 == 0) goto L49
            r6.e()
        L49:
            return
        L4a:
            java.lang.Object r0 = r5.get(r4)
            if (r0 == r6) goto L3a
            boolean r5 = r7.f()
            if (r5 == 0) goto L22
            r7.e()
            goto L22
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.C(long, kotlinx.coroutines.channels.p):void");
    }

    public final Object D(Object obj, kotlin.coroutines.h frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        Throwable thU = u();
        kotlin.p pVar = kotlin.r.b;
        c5028l.resumeWith(Z.b(thU));
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object F(kotlinx.coroutines.channels.p r16, int r17, long r18, kotlin.coroutines.jvm.internal.c r20) {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.F(kotlinx.coroutines.channels.p, int, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void G(J0 j0, boolean z) {
        if (j0 instanceof InterfaceC5026k) {
            kotlin.coroutines.h hVar = (kotlin.coroutines.h) j0;
            kotlin.p pVar = kotlin.r.b;
            hVar.resumeWith(Z.b(z ? t() : u()));
            return;
        }
        if (j0 instanceof v) {
            C5028l c5028l = ((v) j0).a;
            kotlin.p pVar2 = kotlin.r.b;
            c5028l.resumeWith(new o(new m(r())));
            return;
        }
        if (!(j0 instanceof c)) {
            if (j0 instanceof kotlinx.coroutines.selects.f) {
                ((kotlinx.coroutines.selects.e) ((kotlinx.coroutines.selects.f) j0)).g(this, j.l);
                return;
            } else {
                throw new IllegalStateException(("Unexpected waiter: " + j0).toString());
            }
        }
        c cVar = (c) j0;
        C5028l c5028l2 = cVar.b;
        Intrinsics.d(c5028l2);
        cVar.b = null;
        cVar.a = j.l;
        Throwable thR = cVar.c.r();
        if (thR == null) {
            kotlin.p pVar3 = kotlin.r.b;
            c5028l2.resumeWith(Boolean.FALSE);
        } else {
            kotlin.p pVar4 = kotlin.r.b;
            c5028l2.resumeWith(Z.b(thR));
        }
    }

    public final boolean H(Object obj, Object obj2) {
        if (obj instanceof kotlinx.coroutines.selects.f) {
            return ((kotlinx.coroutines.selects.e) ((kotlinx.coroutines.selects.f) obj)).g(this, obj2) == 0;
        }
        if (obj instanceof v) {
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.channels.ReceiveCatching<E of kotlinx.coroutines.channels.BufferedChannel>");
            return j.a(((v) obj).a, new o(obj2), null);
        }
        if (!(obj instanceof c)) {
            if (obj instanceof InterfaceC5026k) {
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.CancellableContinuation<E of kotlinx.coroutines.channels.BufferedChannel>");
                return j.a((InterfaceC5026k) obj, obj2, null);
            }
            throw new IllegalStateException(("Unexpected receiver type: " + obj).toString());
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.channels.BufferedChannel.BufferedChannelIterator<E of kotlinx.coroutines.channels.BufferedChannel>");
        c cVar = (c) obj;
        C5028l c5028l = cVar.b;
        Intrinsics.d(c5028l);
        cVar.b = null;
        cVar.a = obj2;
        Boolean bool = Boolean.TRUE;
        cVar.c.getClass();
        return j.a(c5028l, bool, null);
    }

    public final boolean I(Object obj, p pVar, int i2) {
        kotlinx.coroutines.selects.i iVar;
        if (obj instanceof InterfaceC5026k) {
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.CancellableContinuation<kotlin.Unit>");
            return j.a((InterfaceC5026k) obj, Unit.a, null);
        }
        if (!(obj instanceof kotlinx.coroutines.selects.f)) {
            throw new IllegalStateException(("Unexpected waiter: " + obj).toString());
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.selects.SelectImplementation<*>");
        int iG = ((kotlinx.coroutines.selects.e) obj).g(this, Unit.a);
        if (iG == 0) {
            iVar = kotlinx.coroutines.selects.i.a;
        } else if (iG == 1) {
            iVar = kotlinx.coroutines.selects.i.b;
        } else if (iG == 2) {
            iVar = kotlinx.coroutines.selects.i.c;
        } else {
            if (iG != 3) {
                throw new IllegalStateException(("Unexpected internal result: " + iG).toString());
            }
            iVar = kotlinx.coroutines.selects.i.d;
        }
        if (iVar == kotlinx.coroutines.selects.i.b) {
            pVar.n(i2, null);
        }
        return iVar == kotlinx.coroutines.selects.i.a;
    }

    public final Object J(p pVar, int i2, long j2, Object obj) {
        Object objL = pVar.l(i2);
        AtomicReferenceArray atomicReferenceArray = pVar.f;
        AtomicLongFieldUpdater atomicLongFieldUpdater = b;
        if (objL == null) {
            if (j2 >= (atomicLongFieldUpdater.get(this) & 1152921504606846975L)) {
                if (obj == null) {
                    return j.n;
                }
                if (pVar.k(i2, objL, obj)) {
                    p();
                    return j.m;
                }
            }
        } else if (objL == j.d && pVar.k(i2, objL, j.i)) {
            p();
            Object obj2 = atomicReferenceArray.get(i2 * 2);
            pVar.n(i2, null);
            return obj2;
        }
        while (true) {
            Object objL2 = pVar.l(i2);
            if (objL2 == null || objL2 == j.e) {
                if (j2 < (atomicLongFieldUpdater.get(this) & 1152921504606846975L)) {
                    if (pVar.k(i2, objL2, j.h)) {
                        p();
                        return j.o;
                    }
                } else {
                    if (obj == null) {
                        return j.n;
                    }
                    if (pVar.k(i2, objL2, obj)) {
                        p();
                        return j.m;
                    }
                }
            } else {
                if (objL2 != j.d) {
                    C1472a c1472a = j.j;
                    if (objL2 != c1472a && objL2 != j.h) {
                        if (objL2 == j.l) {
                            p();
                            return j.o;
                        }
                        if (objL2 != j.g && pVar.k(i2, objL2, j.f)) {
                            boolean z = objL2 instanceof y;
                            if (z) {
                                objL2 = ((y) objL2).a;
                            }
                            if (I(objL2, pVar, i2)) {
                                pVar.o(i2, j.i);
                                p();
                                Object obj3 = atomicReferenceArray.get(i2 * 2);
                                pVar.n(i2, null);
                                return obj3;
                            }
                            pVar.o(i2, c1472a);
                            pVar.i();
                            if (z) {
                                p();
                            }
                            return j.o;
                        }
                    }
                    return j.o;
                }
                if (pVar.k(i2, objL2, j.i)) {
                    p();
                    Object obj4 = atomicReferenceArray.get(i2 * 2);
                    pVar.n(i2, null);
                    return obj4;
                }
            }
        }
    }

    public final int K(p pVar, int i2, Object obj, long j2, Object obj2, boolean z) {
        while (true) {
            Object objL = pVar.l(i2);
            if (objL == null) {
                if (!f(j2) || z) {
                    if (z) {
                        if (pVar.k(i2, null, j.j)) {
                            pVar.i();
                            return 4;
                        }
                    } else {
                        if (obj2 == null) {
                            return 3;
                        }
                        if (pVar.k(i2, null, obj2)) {
                            return 2;
                        }
                    }
                } else if (pVar.k(i2, null, j.d)) {
                    break;
                }
            } else {
                if (objL != j.e) {
                    C1472a c1472a = j.k;
                    if (objL == c1472a) {
                        pVar.n(i2, null);
                        return 5;
                    }
                    if (objL == j.h) {
                        pVar.n(i2, null);
                        return 5;
                    }
                    if (objL == j.l) {
                        pVar.n(i2, null);
                        z();
                        return 4;
                    }
                    pVar.n(i2, null);
                    if (objL instanceof y) {
                        objL = ((y) objL).a;
                    }
                    if (H(objL, obj)) {
                        pVar.o(i2, j.i);
                        return 0;
                    }
                    if (pVar.f.getAndSet((i2 * 2) + 1, c1472a) != c1472a) {
                        pVar.m(i2, true);
                    }
                    return 5;
                }
                if (pVar.k(i2, objL, j.d)) {
                    break;
                }
            }
        }
        return 1;
    }

    public final void L(long j2) {
        AtomicLongFieldUpdater atomicLongFieldUpdater;
        h hVar = this;
        if (hVar.B()) {
            return;
        }
        while (true) {
            atomicLongFieldUpdater = d;
            if (atomicLongFieldUpdater.get(hVar) > j2) {
                break;
            } else {
                hVar = this;
            }
        }
        int i2 = j.c;
        int i3 = 0;
        while (true) {
            AtomicLongFieldUpdater atomicLongFieldUpdater2 = e;
            if (i3 < i2) {
                long j3 = atomicLongFieldUpdater.get(hVar);
                if (j3 == (4611686018427387903L & atomicLongFieldUpdater2.get(hVar)) && j3 == atomicLongFieldUpdater.get(hVar)) {
                    return;
                } else {
                    i3++;
                }
            } else {
                while (true) {
                    long j4 = atomicLongFieldUpdater2.get(hVar);
                    if (atomicLongFieldUpdater2.compareAndSet(hVar, j4, (j4 & 4611686018427387903L) + 4611686018427387904L)) {
                        break;
                    } else {
                        hVar = this;
                    }
                }
                while (true) {
                    long j5 = atomicLongFieldUpdater.get(hVar);
                    long j6 = atomicLongFieldUpdater2.get(hVar);
                    long j7 = j6 & 4611686018427387903L;
                    boolean z = (j6 & 4611686018427387904L) != 0;
                    if (j5 == j7 && j5 == atomicLongFieldUpdater.get(hVar)) {
                        break;
                    }
                    if (!z) {
                        atomicLongFieldUpdater2.compareAndSet(this, j6, 4611686018427387904L + j7);
                    }
                    hVar = this;
                }
                while (true) {
                    long j8 = atomicLongFieldUpdater2.get(hVar);
                    if (atomicLongFieldUpdater2.compareAndSet(hVar, j8, j8 & 4611686018427387903L)) {
                        return;
                    } else {
                        hVar = this;
                    }
                }
            }
        }
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object c(kotlin.coroutines.jvm.internal.c frame) {
        p pVar;
        Throwable th;
        p pVar2;
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
        p pVar3 = (p) atomicReferenceFieldUpdater.get(this);
        while (!y()) {
            AtomicLongFieldUpdater atomicLongFieldUpdater = c;
            long andIncrement = atomicLongFieldUpdater.getAndIncrement(this);
            long j2 = j.b;
            long j3 = andIncrement / j2;
            int i2 = (int) (andIncrement % j2);
            if (pVar3.c != j3) {
                p pVarQ = q(j3, pVar3);
                if (pVarQ == null) {
                    continue;
                } else {
                    pVar = pVarQ;
                }
            } else {
                pVar = pVar3;
            }
            Object objJ = J(pVar, i2, andIncrement, null);
            C1472a c1472a = j.m;
            if (objJ == c1472a) {
                throw new IllegalStateException("unexpected");
            }
            C1472a c1472a2 = j.o;
            if (objJ == c1472a2) {
                if (andIncrement < v()) {
                    pVar.a();
                }
                pVar3 = pVar;
            } else {
                if (objJ != j.n) {
                    pVar.a();
                    return objJ;
                }
                C5028l c5028lT = E.t(kotlin.coroutines.intrinsics.h.b(frame));
                h hVar = this;
                try {
                    Object objJ2 = hVar.J(pVar, i2, andIncrement, c5028lT);
                    if (objJ2 == c1472a) {
                        c5028lT.a(pVar, i2);
                    } else if (objJ2 == c1472a2) {
                        if (andIncrement < v()) {
                            pVar.a();
                        }
                        p pVar4 = (p) atomicReferenceFieldUpdater.get(this);
                        while (true) {
                            if (y()) {
                                kotlin.p pVar5 = kotlin.r.b;
                                c5028lT.resumeWith(Z.b(t()));
                                break;
                            }
                            C5028l c5028l = c5028lT;
                            try {
                                long andIncrement2 = atomicLongFieldUpdater.getAndIncrement(this);
                                long j4 = j.b;
                                long j5 = andIncrement2 / j4;
                                int i3 = (int) (andIncrement2 % j4);
                                if (pVar4.c != j5) {
                                    try {
                                        p pVarQ2 = q(j5, pVar4);
                                        if (pVarQ2 == null) {
                                            c5028lT = c5028l;
                                        } else {
                                            pVar2 = pVarQ2;
                                        }
                                    } catch (Throwable th2) {
                                        th = th2;
                                        c5028lT = c5028l;
                                        c5028lT.C();
                                        throw th;
                                    }
                                } else {
                                    pVar2 = pVar4;
                                }
                                Object objJ3 = hVar.J(pVar2, i3, andIncrement2, c5028l);
                                p pVar6 = pVar2;
                                c5028lT = c5028l;
                                if (objJ3 == j.m) {
                                    c5028lT.a(pVar6, i3);
                                    break;
                                }
                                if (objJ3 == j.o) {
                                    if (andIncrement2 < v()) {
                                        pVar6.a();
                                    }
                                    hVar = this;
                                    pVar4 = pVar6;
                                } else {
                                    if (objJ3 == j.n) {
                                        throw new IllegalStateException("unexpected");
                                    }
                                    pVar6.a();
                                    c5028lT.m(objJ3, null);
                                }
                            } catch (Throwable th3) {
                                th = th3;
                                c5028lT = c5028l;
                                th = th;
                                c5028lT.C();
                                throw th;
                            }
                        }
                    } else {
                        pVar.a();
                        c5028lT.m(objJ2, null);
                    }
                    Object objQ = c5028lT.q();
                    if (objQ == kotlin.coroutines.intrinsics.a.a) {
                        Intrinsics.checkNotNullParameter(frame, "frame");
                    }
                    return objQ;
                } catch (Throwable th4) {
                    th = th4;
                }
            }
        }
        Throwable thT = t();
        int i4 = kotlinx.coroutines.internal.r.a;
        throw thT;
    }

    @Override // kotlinx.coroutines.channels.w
    public final com.quizlet.login.common.interactors.d e() {
        O.d(3, d.a);
        O.d(3, e.a);
        return new com.quizlet.login.common.interactors.d(this, (b) null);
    }

    public final boolean f(long j2) {
        return j2 < d.get(this) || j2 < c.get(this) + ((long) this.a);
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object g(kotlin.coroutines.jvm.internal.i iVar) {
        return E(this, iVar);
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object h() {
        p pVar;
        AtomicLongFieldUpdater atomicLongFieldUpdater = c;
        long j2 = atomicLongFieldUpdater.get(this);
        long j3 = b.get(this);
        if (x(j3, true)) {
            return new m(r());
        }
        long j4 = j3 & 1152921504606846975L;
        n nVar = o.b;
        if (j2 >= j4) {
            return nVar;
        }
        Object obj = j.k;
        p pVar2 = (p) g.get(this);
        while (!y()) {
            long andIncrement = atomicLongFieldUpdater.getAndIncrement(this);
            long j5 = j.b;
            long j6 = andIncrement / j5;
            int i2 = (int) (andIncrement % j5);
            if (pVar2.c != j6) {
                p pVarQ = q(j6, pVar2);
                if (pVarQ == null) {
                    continue;
                } else {
                    pVar = pVarQ;
                }
            } else {
                pVar = pVar2;
            }
            Object objJ = J(pVar, i2, andIncrement, obj);
            p pVar3 = pVar;
            if (objJ == j.m) {
                J0 j0 = obj instanceof J0 ? (J0) obj : null;
                if (j0 != null) {
                    j0.a(pVar3, i2);
                }
                L(andIncrement);
                pVar3.i();
                return nVar;
            }
            if (objJ != j.o) {
                if (objJ == j.n) {
                    throw new IllegalStateException("unexpected");
                }
                pVar3.a();
                return objJ;
            }
            if (andIncrement < v()) {
                pVar3.a();
            }
            pVar2 = pVar3;
        }
        return new m(r());
    }

    public final boolean i(Throwable th) {
        return k(th, false);
    }

    @Override // kotlinx.coroutines.channels.w
    public final c iterator() {
        return new c(this);
    }

    @Override // kotlinx.coroutines.channels.w
    public final void j(CancellationException cancellationException) {
        if (cancellationException == null) {
            cancellationException = new CancellationException("Channel was cancelled");
        }
        k(cancellationException, true);
    }

    public final boolean k(Throwable th, boolean z) {
        h hVar;
        boolean z2;
        long j2;
        long j3;
        long j4;
        Object obj;
        long j5;
        long j6;
        AtomicLongFieldUpdater atomicLongFieldUpdater = b;
        if (!z) {
            hVar = this;
            break;
        }
        do {
            j6 = atomicLongFieldUpdater.get(this);
            if (((int) (j6 >> 60)) != 0) {
                hVar = this;
                break;
            }
            p pVar = j.a;
            hVar = this;
        } while (!atomicLongFieldUpdater.compareAndSet(hVar, j6, (j6 & 1152921504606846975L) + (1 << 60)));
        C1472a c1472a = j.s;
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = i;
            if (atomicReferenceFieldUpdater.compareAndSet(this, c1472a, th)) {
                z2 = true;
                break;
            }
            if (atomicReferenceFieldUpdater.get(this) != c1472a) {
                z2 = false;
                break;
            }
        }
        if (z) {
            do {
                j5 = atomicLongFieldUpdater.get(this);
            } while (!atomicLongFieldUpdater.compareAndSet(hVar, j5, (3 << 60) + (j5 & 1152921504606846975L)));
        } else {
            do {
                j2 = atomicLongFieldUpdater.get(this);
                int i2 = (int) (j2 >> 60);
                if (i2 == 0) {
                    j3 = j2 & 1152921504606846975L;
                    j4 = 2;
                } else {
                    if (i2 != 1) {
                        break;
                    }
                    j3 = j2 & 1152921504606846975L;
                    j4 = 3;
                }
            } while (!atomicLongFieldUpdater.compareAndSet(hVar, j2, (j4 << 60) + j3));
        }
        z();
        if (z2) {
            loop3: while (true) {
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = j;
                obj = atomicReferenceFieldUpdater2.get(this);
                C1472a c1472a2 = obj == null ? j.q : j.r;
                while (!atomicReferenceFieldUpdater2.compareAndSet(this, obj, c1472a2)) {
                    if (atomicReferenceFieldUpdater2.get(this) != obj) {
                        break;
                    }
                }
            }
            if (obj != null) {
                O.d(1, obj);
                ((Function1) obj).invoke(r());
                return z2;
            }
        }
        return z2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x008f, code lost:
    
        r1 = (kotlinx.coroutines.channels.p) ((kotlinx.coroutines.internal.c) kotlinx.coroutines.internal.c.b.get(r1));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.channels.p l(long r13) {
        /*
            Method dump skipped, instructions count: 308
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.l(long):kotlinx.coroutines.channels.p");
    }

    public final void m(long j2) {
        p pVar = (p) g.get(this);
        while (true) {
            AtomicLongFieldUpdater atomicLongFieldUpdater = c;
            long j3 = atomicLongFieldUpdater.get(this);
            if (j2 < Math.max(this.a + j3, d.get(this))) {
                return;
            }
            if (atomicLongFieldUpdater.compareAndSet(this, j3, 1 + j3)) {
                long j4 = j.b;
                long j5 = j3 / j4;
                int i2 = (int) (j3 % j4);
                if (pVar.c != j5) {
                    p pVarQ = q(j5, pVar);
                    if (pVarQ != null) {
                        pVar = pVarQ;
                    }
                }
                p pVar2 = pVar;
                if (J(pVar2, i2, j3, null) != j.o || j3 < v()) {
                    pVar2.a();
                }
                pVar = pVar2;
            }
        }
    }

    @Override // kotlinx.coroutines.channels.x
    public final void n(Function1 function1) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        do {
            atomicReferenceFieldUpdater = j;
            if (atomicReferenceFieldUpdater.compareAndSet(this, null, function1)) {
                return;
            }
        } while (atomicReferenceFieldUpdater.get(this) == null);
        while (true) {
            Object obj = atomicReferenceFieldUpdater.get(this);
            C1472a c1472a = j.q;
            if (obj != c1472a) {
                if (obj == j.r) {
                    throw new IllegalStateException("Another handler was already registered and successfully invoked");
                }
                throw new IllegalStateException(("Another handler is already registered: " + obj).toString());
            }
            C1472a c1472a2 = j.r;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, c1472a, c1472a2)) {
                if (atomicReferenceFieldUpdater.get(this) != c1472a) {
                    break;
                }
            }
            function1.invoke(r());
            return;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00bf A[SYNTHETIC] */
    @Override // kotlinx.coroutines.channels.x
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(java.lang.Object r16) {
        /*
            r15 = this;
            java.util.concurrent.atomic.AtomicLongFieldUpdater r8 = kotlinx.coroutines.channels.h.b
            long r1 = r8.get(r15)
            r9 = 0
            boolean r3 = r15.x(r1, r9)
            r10 = 1
            r11 = 1152921504606846975(0xfffffffffffffff, double:1.2882297539194265E-231)
            if (r3 == 0) goto L15
            r1 = r9
            goto L1b
        L15:
            long r1 = r1 & r11
            boolean r1 = r15.f(r1)
            r1 = r1 ^ r10
        L1b:
            kotlinx.coroutines.channels.n r13 = kotlinx.coroutines.channels.o.b
            if (r1 == 0) goto L20
            return r13
        L20:
            com.android.billingclient.api.a r6 = kotlinx.coroutines.channels.j.j
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r1 = kotlinx.coroutines.channels.h.f
            java.lang.Object r1 = r1.get(r15)
            kotlinx.coroutines.channels.p r1 = (kotlinx.coroutines.channels.p) r1
        L2a:
            long r2 = r8.getAndIncrement(r15)
            long r4 = r2 & r11
            boolean r7 = r15.x(r2, r9)
            int r14 = kotlinx.coroutines.channels.j.b
            long r2 = (long) r14
            long r11 = r4 / r2
            long r2 = r4 % r2
            int r2 = (int) r2
            long r9 = r1.c
            int r3 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r3 == 0) goto L5d
            kotlinx.coroutines.channels.p r3 = a(r15, r11, r1)
            if (r3 != 0) goto L5c
            if (r7 == 0) goto L54
            java.lang.Throwable r1 = r15.u()
            kotlinx.coroutines.channels.m r2 = new kotlinx.coroutines.channels.m
            r2.<init>(r1)
            return r2
        L54:
            r9 = 0
            r10 = 1
        L56:
            r11 = 1152921504606846975(0xfffffffffffffff, double:1.2882297539194265E-231)
            goto L2a
        L5c:
            r1 = r3
        L5d:
            r0 = r15
            r3 = r16
            int r9 = d(r0, r1, r2, r3, r4, r6, r7)
            if (r9 == 0) goto Lbf
            r3 = 1
            if (r9 == r3) goto Lbc
            r10 = 2
            if (r9 == r10) goto L9b
            r2 = 3
            if (r9 == r2) goto L93
            r2 = 4
            if (r9 == r2) goto L7c
            r2 = 5
            if (r9 == r2) goto L76
            goto L79
        L76:
            r1.a()
        L79:
            r10 = r3
            r9 = 0
            goto L56
        L7c:
            java.util.concurrent.atomic.AtomicLongFieldUpdater r2 = kotlinx.coroutines.channels.h.c
            long r2 = r2.get(r15)
            int r2 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r2 >= 0) goto L89
            r1.a()
        L89:
            java.lang.Throwable r1 = r15.u()
            kotlinx.coroutines.channels.m r2 = new kotlinx.coroutines.channels.m
            r2.<init>(r1)
            return r2
        L93:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "unexpected"
            r1.<init>(r2)
            throw r1
        L9b:
            if (r7 == 0) goto Laa
            r1.i()
            java.lang.Throwable r1 = r15.u()
            kotlinx.coroutines.channels.m r2 = new kotlinx.coroutines.channels.m
            r2.<init>(r1)
            return r2
        Laa:
            boolean r3 = r6 instanceof kotlinx.coroutines.J0
            if (r3 == 0) goto Lb1
            kotlinx.coroutines.J0 r6 = (kotlinx.coroutines.J0) r6
            goto Lb2
        Lb1:
            r6 = 0
        Lb2:
            if (r6 == 0) goto Lb8
            int r2 = r2 + r14
            r6.a(r1, r2)
        Lb8:
            r1.i()
            return r13
        Lbc:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        Lbf:
            r1.a()
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.o(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:102:0x018e, code lost:
    
        w(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0191, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p() {
        /*
            Method dump skipped, instructions count: 402
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.p():void");
    }

    public final p q(long j2, p pVar) {
        Object objB;
        AtomicLongFieldUpdater atomicLongFieldUpdater;
        long j3;
        p pVar2 = j.a;
        i iVar = i.a;
        loop0: while (true) {
            objB = kotlinx.coroutines.internal.b.b(pVar, j2, iVar);
            if (!kotlinx.coroutines.internal.b.e(objB)) {
                kotlinx.coroutines.internal.q qVarC = kotlinx.coroutines.internal.b.c(objB);
                while (true) {
                    AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
                    kotlinx.coroutines.internal.q qVar = (kotlinx.coroutines.internal.q) atomicReferenceFieldUpdater.get(this);
                    if (qVar.c >= qVarC.c) {
                        break loop0;
                    }
                    if (!qVarC.j()) {
                        break;
                    }
                    while (!atomicReferenceFieldUpdater.compareAndSet(this, qVar, qVarC)) {
                        if (atomicReferenceFieldUpdater.get(this) != qVar) {
                            if (qVarC.f()) {
                                qVarC.e();
                            }
                        }
                    }
                    if (qVar.f()) {
                        qVar.e();
                    }
                }
            } else {
                break;
            }
        }
        if (kotlinx.coroutines.internal.b.e(objB)) {
            z();
            if (pVar.c * j.b < v()) {
                pVar.a();
                return null;
            }
        } else {
            p pVar3 = (p) kotlinx.coroutines.internal.b.c(objB);
            boolean zB = B();
            long j4 = pVar3.c;
            if (!zB && j2 <= d.get(this) / j.b) {
                while (true) {
                    AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = h;
                    kotlinx.coroutines.internal.q qVar2 = (kotlinx.coroutines.internal.q) atomicReferenceFieldUpdater2.get(this);
                    if (qVar2.c >= j4 || !pVar3.j()) {
                        break;
                    }
                    while (!atomicReferenceFieldUpdater2.compareAndSet(this, qVar2, pVar3)) {
                        if (atomicReferenceFieldUpdater2.get(this) != qVar2) {
                            if (pVar3.f()) {
                                pVar3.e();
                            }
                        }
                    }
                    if (qVar2.f()) {
                        qVar2.e();
                    }
                }
            }
            if (j4 <= j2) {
                return pVar3;
            }
            long j5 = j4 * j.b;
            do {
                atomicLongFieldUpdater = c;
                j3 = atomicLongFieldUpdater.get(this);
                if (j3 >= j5) {
                    break;
                }
            } while (!atomicLongFieldUpdater.compareAndSet(this, j3, j5));
            if (j4 * j.b < v()) {
                pVar3.a();
            }
        }
        return null;
    }

    public final Throwable r() {
        return (Throwable) i.get(this);
    }

    /* JADX WARN: Code restructure failed: missing block: B:108:0x01a0, code lost:
    
        return kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c0, code lost:
    
        b(r1, r4, r7);
     */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0174  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0182 A[RETURN] */
    @Override // kotlinx.coroutines.channels.x
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object s(java.lang.Object r23, kotlin.coroutines.h r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 417
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.s(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }

    public final Throwable t() {
        Throwable thR = r();
        return thR == null ? new ClosedReceiveChannelException("Channel was closed") : thR;
    }

    /* JADX WARN: Code restructure failed: missing block: B:85:0x01b7, code lost:
    
        r16 = r7;
        r3 = (kotlinx.coroutines.channels.p) r3.c();
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01c0, code lost:
    
        if (r3 != null) goto L92;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String toString() {
        /*
            Method dump skipped, instructions count: 492
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.toString():java.lang.String");
    }

    public final Throwable u() {
        Throwable thR = r();
        return thR == null ? new ClosedSendChannelException("Channel was closed") : thR;
    }

    public final long v() {
        return b.get(this) & 1152921504606846975L;
    }

    /* JADX WARN: Code restructure failed: missing block: B:53:0x00a2, code lost:
    
        r0 = (kotlinx.coroutines.channels.p) ((kotlinx.coroutines.internal.c) kotlinx.coroutines.internal.c.b.get(r0));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean x(long r15, boolean r17) {
        /*
            Method dump skipped, instructions count: 368
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.h.x(long, boolean):boolean");
    }

    public final boolean y() {
        return x(b.get(this), true);
    }

    public final boolean z() {
        return x(b.get(this), false);
    }
}
