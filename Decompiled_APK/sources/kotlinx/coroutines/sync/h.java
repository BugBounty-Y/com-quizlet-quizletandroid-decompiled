package kotlinx.coroutines.sync;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlinx.coroutines.InterfaceC5026k;
import kotlinx.coroutines.J0;
import kotlinx.coroutines.internal.q;

/* loaded from: classes3.dex */
public class h {
    public static final /* synthetic */ AtomicReferenceFieldUpdater c = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "head$volatile");
    public static final /* synthetic */ AtomicLongFieldUpdater d = AtomicLongFieldUpdater.newUpdater(h.class, "deqIdx$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater e = AtomicReferenceFieldUpdater.newUpdater(h.class, Object.class, "tail$volatile");
    public static final /* synthetic */ AtomicLongFieldUpdater f = AtomicLongFieldUpdater.newUpdater(h.class, "enqIdx$volatile");
    public static final /* synthetic */ AtomicIntegerFieldUpdater g = AtomicIntegerFieldUpdater.newUpdater(h.class, "_availablePermits$volatile");
    private volatile /* synthetic */ int _availablePermits$volatile;
    public final int a;
    public final androidx.navigation.serialization.i b;
    private volatile /* synthetic */ long deqIdx$volatile;
    private volatile /* synthetic */ long enqIdx$volatile;
    private volatile /* synthetic */ Object head$volatile;
    private volatile /* synthetic */ Object tail$volatile;

    public h(int i, int i2) {
        this.a = i;
        if (i <= 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Semaphore should have at least 1 permit, but had ").toString());
        }
        if (i2 < 0 || i2 > i) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "The number of acquired permits should be in 0..").toString());
        }
        k kVar = new k(0L, null, 2);
        this.head$volatile = kVar;
        this.tail$volatile = kVar;
        this._availablePermits$volatile = i - i2;
        this.b = new androidx.navigation.serialization.i(this, 8);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0025, code lost:
    
        r1.m(kotlin.Unit.a, r4.b);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
        L0:
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r0 = kotlinx.coroutines.sync.h.g
            int r1 = r0.getAndDecrement(r4)
            int r2 = r4.a
            if (r1 > r2) goto L0
            if (r1 <= 0) goto Lf
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        Lf:
            kotlin.coroutines.h r1 = kotlin.coroutines.intrinsics.h.b(r5)
            kotlinx.coroutines.l r1 = kotlinx.coroutines.E.t(r1)
            boolean r3 = r4.b(r1)     // Catch: java.lang.Throwable -> L34
            if (r3 != 0) goto L36
        L1d:
            int r3 = r0.getAndDecrement(r4)     // Catch: java.lang.Throwable -> L34
            if (r3 > r2) goto L1d
            if (r3 <= 0) goto L2d
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L34
            androidx.navigation.serialization.i r2 = r4.b     // Catch: java.lang.Throwable -> L34
            r1.m(r0, r2)     // Catch: java.lang.Throwable -> L34
            goto L36
        L2d:
            boolean r3 = r4.b(r1)     // Catch: java.lang.Throwable -> L34
            if (r3 == 0) goto L1d
            goto L36
        L34:
            r5 = move-exception
            goto L4e
        L36:
            java.lang.Object r0 = r1.q()
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            if (r0 != r1) goto L43
            java.lang.String r2 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
        L43:
            if (r0 != r1) goto L46
            goto L48
        L46:
            kotlin.Unit r0 = kotlin.Unit.a
        L48:
            if (r0 != r1) goto L4b
            return r0
        L4b:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L4e:
            r1.C()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.sync.h.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final boolean b(J0 j0) {
        Object objB;
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = e;
        k kVar = (k) atomicReferenceFieldUpdater.get(this);
        long andIncrement = f.getAndIncrement(this);
        f fVar = f.a;
        long j = andIncrement / j.f;
        loop0: while (true) {
            objB = kotlinx.coroutines.internal.b.b(kVar, j, fVar);
            if (!kotlinx.coroutines.internal.b.e(objB)) {
                q qVarC = kotlinx.coroutines.internal.b.c(objB);
                while (true) {
                    q qVar = (q) atomicReferenceFieldUpdater.get(this);
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
        k kVar2 = (k) kotlinx.coroutines.internal.b.c(objB);
        int i = (int) (andIncrement % j.f);
        AtomicReferenceArray atomicReferenceArray = kVar2.e;
        while (!atomicReferenceArray.compareAndSet(i, null, j0)) {
            if (atomicReferenceArray.get(i) != null) {
                C1472a c1472a = j.b;
                C1472a c1472a2 = j.c;
                while (!atomicReferenceArray.compareAndSet(i, c1472a, c1472a2)) {
                    if (atomicReferenceArray.get(i) != c1472a) {
                        return false;
                    }
                }
                if (j0 instanceof InterfaceC5026k) {
                    ((InterfaceC5026k) j0).m(Unit.a, this.b);
                    return true;
                }
                if (j0 instanceof kotlinx.coroutines.selects.f) {
                    ((kotlinx.coroutines.selects.e) ((kotlinx.coroutines.selects.f) j0)).e = Unit.a;
                    return true;
                }
                throw new IllegalStateException(("unexpected: " + j0).toString());
            }
        }
        j0.a(kVar2, i);
        return true;
    }

    public final void c() {
        int i;
        Object objB;
        boolean z;
        do {
            AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = g;
            int andIncrement = atomicIntegerFieldUpdater.getAndIncrement(this);
            int i2 = this.a;
            if (andIncrement >= i2) {
                do {
                    i = atomicIntegerFieldUpdater.get(this);
                    if (i <= i2) {
                        break;
                    }
                } while (!atomicIntegerFieldUpdater.compareAndSet(this, i, i2));
                throw new IllegalStateException(("The number of released permits cannot be greater than " + i2).toString());
            }
            if (andIncrement >= 0) {
                return;
            }
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = c;
            k kVar = (k) atomicReferenceFieldUpdater.get(this);
            long andIncrement2 = d.getAndIncrement(this);
            long j = andIncrement2 / j.f;
            g gVar = g.a;
            while (true) {
                objB = kotlinx.coroutines.internal.b.b(kVar, j, gVar);
                if (kotlinx.coroutines.internal.b.e(objB)) {
                    break;
                }
                q qVarC = kotlinx.coroutines.internal.b.c(objB);
                while (true) {
                    q qVar = (q) atomicReferenceFieldUpdater.get(this);
                    if (qVar.c >= qVarC.c) {
                        break;
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
            }
            k kVar2 = (k) kotlinx.coroutines.internal.b.c(objB);
            kVar2.a();
            z = false;
            if (kVar2.c <= j) {
                int i3 = (int) (andIncrement2 % j.f);
                C1472a c1472a = j.b;
                AtomicReferenceArray atomicReferenceArray = kVar2.e;
                Object andSet = atomicReferenceArray.getAndSet(i3, c1472a);
                if (andSet == null) {
                    int i4 = j.a;
                    for (int i5 = 0; i5 < i4; i5++) {
                        if (atomicReferenceArray.get(i3) == j.c) {
                            z = true;
                            break;
                        }
                    }
                    C1472a c1472a2 = j.b;
                    C1472a c1472a3 = j.d;
                    while (true) {
                        if (!atomicReferenceArray.compareAndSet(i3, c1472a2, c1472a3)) {
                            if (atomicReferenceArray.get(i3) != c1472a2) {
                                break;
                            }
                        } else {
                            z = true;
                            break;
                        }
                    }
                    z = !z;
                } else if (andSet != j.e) {
                    if (!(andSet instanceof InterfaceC5026k)) {
                        if (!(andSet instanceof kotlinx.coroutines.selects.f)) {
                            throw new IllegalStateException(("unexpected: " + andSet).toString());
                        }
                        if (((kotlinx.coroutines.selects.e) ((kotlinx.coroutines.selects.f) andSet)).g(this, Unit.a) == 0) {
                            z = true;
                            break;
                            break;
                        }
                    } else {
                        InterfaceC5026k interfaceC5026k = (InterfaceC5026k) andSet;
                        C1472a c1472aK = interfaceC5026k.k(Unit.a, this.b);
                        if (c1472aK != null) {
                            interfaceC5026k.t(c1472aK);
                            z = true;
                            break;
                            break;
                        }
                    }
                }
            }
        } while (!z);
    }
}
