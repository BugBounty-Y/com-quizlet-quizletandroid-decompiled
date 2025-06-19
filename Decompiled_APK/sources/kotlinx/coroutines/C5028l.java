package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5028l extends M implements InterfaceC5026k, kotlin.coroutines.jvm.internal.d, J0 {
    public static final /* synthetic */ AtomicIntegerFieldUpdater f = AtomicIntegerFieldUpdater.newUpdater(C5028l.class, "_decisionAndIndex$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater g = AtomicReferenceFieldUpdater.newUpdater(C5028l.class, Object.class, "_state$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater h = AtomicReferenceFieldUpdater.newUpdater(C5028l.class, Object.class, "_parentHandle$volatile");
    private volatile /* synthetic */ int _decisionAndIndex$volatile;
    private volatile /* synthetic */ Object _parentHandle$volatile;
    private volatile /* synthetic */ Object _state$volatile;
    public final kotlin.coroutines.h d;
    public final CoroutineContext e;

    public C5028l(int i, kotlin.coroutines.h hVar) {
        super(i);
        this.d = hVar;
        this.e = hVar.getContext();
        this._decisionAndIndex$volatile = 536870911;
        this._state$volatile = C4974b.a;
    }

    public static void A(w0 w0Var, Object obj) {
        throw new IllegalStateException(("It's prohibited to register multiple handlers, tried to register " + w0Var + ", already has " + obj).toString());
    }

    public static Object F(w0 w0Var, Object obj, int i, kotlin.jvm.functions.c cVar) {
        if (obj instanceof C5036u) {
            return obj;
        }
        if (i != 1 && i != 2) {
            return obj;
        }
        if (cVar != null || (w0Var instanceof InterfaceC5024j)) {
            return new C5035t(obj, w0Var instanceof InterfaceC5024j ? (InterfaceC5024j) w0Var : null, cVar, (CancellationException) null, 16);
        }
        return obj;
    }

    public String B() {
        return "CancellableContinuation";
    }

    public final void C() {
        kotlin.coroutines.h hVar = this.d;
        Throwable th = null;
        kotlinx.coroutines.internal.f fVar = hVar instanceof kotlinx.coroutines.internal.f ? (kotlinx.coroutines.internal.f) hVar : null;
        if (fVar != null) {
            loop0: while (true) {
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = kotlinx.coroutines.internal.f.h;
                Object obj = atomicReferenceFieldUpdater.get(fVar);
                C1472a c1472a = kotlinx.coroutines.internal.b.c;
                if (obj == c1472a) {
                    while (!atomicReferenceFieldUpdater.compareAndSet(fVar, c1472a, this)) {
                        if (atomicReferenceFieldUpdater.get(fVar) != c1472a) {
                            break;
                        }
                    }
                    break loop0;
                } else {
                    if (!(obj instanceof Throwable)) {
                        throw new IllegalStateException(("Inconsistent state " + obj).toString());
                    }
                    while (!atomicReferenceFieldUpdater.compareAndSet(fVar, obj, null)) {
                        if (atomicReferenceFieldUpdater.get(fVar) != obj) {
                            throw new IllegalArgumentException("Failed requirement.");
                        }
                    }
                    th = (Throwable) obj;
                }
            }
            if (th == null) {
                return;
            }
            n();
            b(th);
        }
    }

    public final void D(Object obj, int i, kotlin.jvm.functions.c cVar) throws DispatchException {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
            Object obj2 = atomicReferenceFieldUpdater.get(this);
            if (obj2 instanceof w0) {
                Object objF = F((w0) obj2, obj, i, cVar);
                while (!atomicReferenceFieldUpdater.compareAndSet(this, obj2, objF)) {
                    if (atomicReferenceFieldUpdater.get(this) != obj2) {
                        break;
                    }
                }
                if (!z()) {
                    n();
                }
                o(i);
                return;
            }
            if (obj2 instanceof C5029m) {
                C5029m c5029m = (C5029m) obj2;
                c5029m.getClass();
                if (C5029m.c.compareAndSet(c5029m, 0, 1)) {
                    if (cVar != null) {
                        j(cVar, c5029m.a, obj);
                        return;
                    }
                    return;
                }
            }
            throw new IllegalStateException(("Already resumed, but proposed with update " + obj).toString());
        }
    }

    public final void E(AbstractC5040y abstractC5040y, Unit unit) throws DispatchException {
        kotlin.coroutines.h hVar = this.d;
        kotlinx.coroutines.internal.f fVar = hVar instanceof kotlinx.coroutines.internal.f ? (kotlinx.coroutines.internal.f) hVar : null;
        D(unit, (fVar != null ? fVar.d : null) == abstractC5040y ? 4 : this.c, null);
    }

    public final C1472a G(Object obj, kotlin.jvm.functions.c cVar) {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
            Object obj2 = atomicReferenceFieldUpdater.get(this);
            boolean z = obj2 instanceof w0;
            C1472a c1472a = E.a;
            if (!z) {
                boolean z2 = obj2 instanceof C5035t;
                return null;
            }
            Object objF = F((w0) obj2, obj, this.c, cVar);
            while (!atomicReferenceFieldUpdater.compareAndSet(this, obj2, objF)) {
                if (atomicReferenceFieldUpdater.get(this) != obj2) {
                    break;
                }
            }
            if (!z()) {
                n();
            }
            return c1472a;
        }
    }

    @Override // kotlinx.coroutines.J0
    public final void a(kotlinx.coroutines.internal.q qVar, int i) {
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater;
        int i2;
        do {
            atomicIntegerFieldUpdater = f;
            i2 = atomicIntegerFieldUpdater.get(this);
            if ((i2 & 536870911) != 536870911) {
                throw new IllegalStateException("invokeOnCancellation should be called at most once");
            }
        } while (!atomicIntegerFieldUpdater.compareAndSet(this, i2, ((i2 >> 29) << 29) + i));
        v(qVar);
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final boolean b(Throwable th) {
        Throwable cancellationException;
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
            Object obj = atomicReferenceFieldUpdater.get(this);
            if (!(obj instanceof w0)) {
                return false;
            }
            boolean z = (obj instanceof InterfaceC5024j) || (obj instanceof kotlinx.coroutines.internal.q);
            if (th == null) {
                cancellationException = new CancellationException("Continuation " + this + " was cancelled normally");
            } else {
                cancellationException = th;
            }
            C5029m c5029m = new C5029m(cancellationException, z);
            while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, c5029m)) {
                if (atomicReferenceFieldUpdater.get(this) != obj) {
                    break;
                }
            }
            w0 w0Var = (w0) obj;
            if (w0Var instanceof InterfaceC5024j) {
                i((InterfaceC5024j) obj, th);
            } else if (w0Var instanceof kotlinx.coroutines.internal.q) {
                l((kotlinx.coroutines.internal.q) obj, th);
            }
            if (!z()) {
                n();
            }
            o(this.c);
            return true;
        }
    }

    @Override // kotlinx.coroutines.M
    public final void c(CancellationException cancellationException) {
        CancellationException cancellationException2;
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
            Object obj = atomicReferenceFieldUpdater.get(this);
            if (obj instanceof w0) {
                throw new IllegalStateException("Not completed");
            }
            if (obj instanceof C5036u) {
                return;
            }
            if (!(obj instanceof C5035t)) {
                cancellationException2 = cancellationException;
                C5035t c5035t = new C5035t(obj, (InterfaceC5024j) null, (kotlin.jvm.functions.c) null, cancellationException2, 14);
                while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, c5035t)) {
                    if (atomicReferenceFieldUpdater.get(this) != obj) {
                        break;
                    }
                }
                return;
            }
            C5035t c5035t2 = (C5035t) obj;
            if (c5035t2.e != null) {
                throw new IllegalStateException("Must be called at most once");
            }
            C5035t c5035tA = C5035t.a(c5035t2, null, cancellationException, 15);
            while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, c5035tA)) {
                if (atomicReferenceFieldUpdater.get(this) != obj) {
                    cancellationException2 = cancellationException;
                }
            }
            InterfaceC5024j interfaceC5024j = c5035t2.b;
            if (interfaceC5024j != null) {
                i(interfaceC5024j, cancellationException);
            }
            kotlin.jvm.functions.c cVar = c5035t2.c;
            if (cVar != null) {
                j(cVar, cancellationException, c5035t2.a);
                return;
            }
            return;
            cancellationException = cancellationException2;
        }
    }

    @Override // kotlinx.coroutines.M
    public final kotlin.coroutines.h d() {
        return this.d;
    }

    @Override // kotlinx.coroutines.M
    public final Throwable e(Object obj) {
        Throwable thE = super.e(obj);
        if (thE != null) {
            return thE;
        }
        return null;
    }

    @Override // kotlinx.coroutines.M
    public final Object f(Object obj) {
        return obj instanceof C5035t ? ((C5035t) obj).a : obj;
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        kotlin.coroutines.h hVar = this.d;
        if (hVar instanceof kotlin.coroutines.jvm.internal.d) {
            return (kotlin.coroutines.jvm.internal.d) hVar;
        }
        return null;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.e;
    }

    @Override // kotlinx.coroutines.M
    public final Object h() {
        return g.get(this);
    }

    public final void i(InterfaceC5024j interfaceC5024j, Throwable th) {
        try {
            interfaceC5024j.b(th);
        } catch (Throwable th2) {
            E.u(this.e, new CompletionHandlerException("Exception in invokeOnCancellation handler for " + this, th2));
        }
    }

    public final void j(kotlin.jvm.functions.c cVar, Throwable th, Object obj) {
        CoroutineContext coroutineContext = this.e;
        try {
            cVar.invoke(th, obj, coroutineContext);
        } catch (Throwable th2) {
            E.u(coroutineContext, new CompletionHandlerException("Exception in resume onCancellation handler for " + this, th2));
        }
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final C1472a k(Object obj, kotlin.jvm.functions.c cVar) {
        return G(obj, cVar);
    }

    public final void l(kotlinx.coroutines.internal.q qVar, Throwable th) {
        CoroutineContext coroutineContext = this.e;
        int i = f.get(this) & 536870911;
        if (i == 536870911) {
            throw new IllegalStateException("The index for Segment.onCancellation(..) is broken");
        }
        try {
            qVar.h(i, coroutineContext);
        } catch (Throwable th2) {
            E.u(coroutineContext, new CompletionHandlerException("Exception in invokeOnCancellation handler for " + this, th2));
        }
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final void m(Object obj, kotlin.jvm.functions.c cVar) throws DispatchException {
        D(obj, this.c, cVar);
    }

    public final void n() {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = h;
        Q q = (Q) atomicReferenceFieldUpdater.get(this);
        if (q == null) {
            return;
        }
        q.dispose();
        atomicReferenceFieldUpdater.set(this, v0.a);
    }

    public final void o(int i) throws DispatchException {
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater;
        int i2;
        do {
            atomicIntegerFieldUpdater = f;
            i2 = atomicIntegerFieldUpdater.get(this);
            int i3 = i2 >> 29;
            if (i3 != 0) {
                if (i3 != 1) {
                    throw new IllegalStateException("Already resumed");
                }
                boolean z = i == 4;
                kotlin.coroutines.h hVar = this.d;
                if (!z && (hVar instanceof kotlinx.coroutines.internal.f)) {
                    boolean z2 = i == 1 || i == 2;
                    int i4 = this.c;
                    if (z2 == (i4 == 1 || i4 == 2)) {
                        kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVar;
                        AbstractC5040y abstractC5040y = fVar.d;
                        CoroutineContext context = fVar.e.getContext();
                        if (kotlinx.coroutines.internal.b.i(abstractC5040y, context)) {
                            kotlinx.coroutines.internal.b.h(abstractC5040y, context, this);
                            return;
                        }
                        Z zA = C0.a();
                        if (zA.b >= 4294967296L) {
                            zA.l0(this);
                            return;
                        }
                        zA.n0(true);
                        try {
                            E.C(this, hVar, true);
                            do {
                            } while (zA.p0());
                        } finally {
                            try {
                                return;
                            } finally {
                            }
                        }
                        return;
                    }
                }
                E.C(this, hVar, z);
                return;
            }
        } while (!atomicIntegerFieldUpdater.compareAndSet(this, i2, 1073741824 + (536870911 & i2)));
    }

    public Throwable p(q0 q0Var) {
        return q0Var.y();
    }

    public final Object q() {
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater;
        int i;
        boolean z = z();
        do {
            atomicIntegerFieldUpdater = f;
            i = atomicIntegerFieldUpdater.get(this);
            int i2 = i >> 29;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new IllegalStateException("Already suspended");
                }
                if (z) {
                    C();
                }
                Object obj = g.get(this);
                if (obj instanceof C5036u) {
                    throw ((C5036u) obj).a;
                }
                int i3 = this.c;
                if (i3 == 1 || i3 == 2) {
                    InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) this.e.get(C5023i0.a);
                    if (interfaceC5025j0 != null && !interfaceC5025j0.a()) {
                        CancellationException cancellationExceptionY = interfaceC5025j0.y();
                        c(cancellationExceptionY);
                        throw cancellationExceptionY;
                    }
                }
                return f(obj);
            }
        } while (!atomicIntegerFieldUpdater.compareAndSet(this, i, 536870912 + (536870911 & i)));
        if (((Q) h.get(this)) == null) {
            s();
        }
        if (z) {
            C();
        }
        return kotlin.coroutines.intrinsics.a.a;
    }

    public final void r() {
        Q qS = s();
        if (qS != null && y()) {
            qS.dispose();
            h.set(this, v0.a);
        }
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        Throwable thA = kotlin.r.a(obj);
        if (thA != null) {
            obj = new C5036u(thA, false);
        }
        D(obj, this.c, null);
    }

    public final Q s() {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) this.e.get(C5023i0.a);
        if (interfaceC5025j0 == null) {
            return null;
        }
        Q qV = E.v(interfaceC5025j0, true, new C5030n(this, 0));
        do {
            atomicReferenceFieldUpdater = h;
            if (atomicReferenceFieldUpdater.compareAndSet(this, null, qV)) {
                break;
            }
        } while (atomicReferenceFieldUpdater.get(this) == null);
        return qV;
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final void t(Object obj) throws DispatchException {
        o(this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(B());
        sb.append('(');
        sb.append(E.G(this.d));
        sb.append("){");
        Object obj = g.get(this);
        sb.append(obj instanceof w0 ? "Active" : obj instanceof C5029m ? "Cancelled" : "Completed");
        sb.append("}@");
        sb.append(E.r(this));
        return sb.toString();
    }

    public final void u(Function1 function1) {
        v(new C5022i(function1, 1));
    }

    /* JADX WARN: Code restructure failed: missing block: B:63:0x00b7, code lost:
    
        A(r8, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x00ba, code lost:
    
        throw null;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void v(kotlinx.coroutines.w0 r8) {
        /*
            r7 = this;
        L0:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = kotlinx.coroutines.C5028l.g
            java.lang.Object r2 = r0.get(r7)
            boolean r1 = r2 instanceof kotlinx.coroutines.C4974b
            if (r1 == 0) goto L19
        La:
            boolean r1 = r0.compareAndSet(r7, r2, r8)
            if (r1 == 0) goto L12
            goto Lae
        L12:
            java.lang.Object r1 = r0.get(r7)
            if (r1 == r2) goto La
            goto L0
        L19:
            boolean r1 = r2 instanceof kotlinx.coroutines.InterfaceC5024j
            r3 = 0
            if (r1 != 0) goto Lb7
            boolean r1 = r2 instanceof kotlinx.coroutines.internal.q
            if (r1 != 0) goto Lb7
            boolean r1 = r2 instanceof kotlinx.coroutines.C5036u
            if (r1 == 0) goto L5b
            r0 = r2
            kotlinx.coroutines.u r0 = (kotlinx.coroutines.C5036u) r0
            r0.getClass()
            r1 = 1
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r4 = kotlinx.coroutines.C5036u.b
            r5 = 0
            boolean r1 = r4.compareAndSet(r0, r5, r1)
            if (r1 == 0) goto L57
            boolean r1 = r2 instanceof kotlinx.coroutines.C5029m
            if (r1 == 0) goto Lae
            if (r2 == 0) goto L3d
            goto L3e
        L3d:
            r0 = r3
        L3e:
            if (r0 == 0) goto L42
            java.lang.Throwable r3 = r0.a
        L42:
            boolean r0 = r8 instanceof kotlinx.coroutines.InterfaceC5024j
            if (r0 == 0) goto L4c
            kotlinx.coroutines.j r8 = (kotlinx.coroutines.InterfaceC5024j) r8
            r7.i(r8, r3)
            return
        L4c:
            java.lang.String r0 = "null cannot be cast to non-null type kotlinx.coroutines.internal.Segment<*>"
            kotlin.jvm.internal.Intrinsics.e(r8, r0)
            kotlinx.coroutines.internal.q r8 = (kotlinx.coroutines.internal.q) r8
            r7.l(r8, r3)
            return
        L57:
            A(r8, r2)
            throw r3
        L5b:
            boolean r1 = r2 instanceof kotlinx.coroutines.C5035t
            java.lang.String r4 = "null cannot be cast to non-null type kotlinx.coroutines.CancelHandler"
            if (r1 == 0) goto L94
            r1 = r2
            kotlinx.coroutines.t r1 = (kotlinx.coroutines.C5035t) r1
            kotlinx.coroutines.j r5 = r1.b
            if (r5 != 0) goto L90
            boolean r5 = r8 instanceof kotlinx.coroutines.internal.q
            if (r5 == 0) goto L6d
            return
        L6d:
            kotlin.jvm.internal.Intrinsics.e(r8, r4)
            r4 = r8
            kotlinx.coroutines.j r4 = (kotlinx.coroutines.InterfaceC5024j) r4
            java.lang.Throwable r5 = r1.e
            if (r5 == 0) goto L7b
            r7.i(r4, r5)
            return
        L7b:
            r5 = 29
            kotlinx.coroutines.t r1 = kotlinx.coroutines.C5035t.a(r1, r4, r3, r5)
        L81:
            boolean r3 = r0.compareAndSet(r7, r2, r1)
            if (r3 == 0) goto L88
            goto Lae
        L88:
            java.lang.Object r3 = r0.get(r7)
            if (r3 == r2) goto L81
            goto L0
        L90:
            A(r8, r2)
            throw r3
        L94:
            boolean r1 = r8 instanceof kotlinx.coroutines.internal.q
            if (r1 == 0) goto L99
            return
        L99:
            kotlin.jvm.internal.Intrinsics.e(r8, r4)
            r3 = r8
            kotlinx.coroutines.j r3 = (kotlinx.coroutines.InterfaceC5024j) r3
            kotlinx.coroutines.t r1 = new kotlinx.coroutines.t
            r4 = 0
            r5 = 0
            r6 = 28
            r1.<init>(r2, r3, r4, r5, r6)
        La8:
            boolean r3 = r0.compareAndSet(r7, r2, r1)
            if (r3 == 0) goto Laf
        Lae:
            return
        Laf:
            java.lang.Object r3 = r0.get(r7)
            if (r3 == r2) goto La8
            goto L0
        Lb7:
            A(r8, r2)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.C5028l.v(kotlinx.coroutines.w0):void");
    }

    public final boolean w() {
        return g.get(this) instanceof w0;
    }

    public final boolean x() {
        return g.get(this) instanceof C5029m;
    }

    public final boolean y() {
        return !(g.get(this) instanceof w0);
    }

    public final boolean z() {
        if (this.c != 2) {
            return false;
        }
        kotlin.coroutines.h hVar = this.d;
        Intrinsics.e(hVar, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>");
        return kotlinx.coroutines.internal.f.h.get((kotlinx.coroutines.internal.f) hVar) != null;
    }
}
