package kotlinx.coroutines;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.C4937f;
import kotlin.Unit;
import kotlin.collections.C4931w;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;

/* loaded from: classes3.dex */
public class q0 implements InterfaceC5025j0, x0 {
    public static final /* synthetic */ AtomicReferenceFieldUpdater a = AtomicReferenceFieldUpdater.newUpdater(q0.class, Object.class, "_state$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater b = AtomicReferenceFieldUpdater.newUpdater(q0.class, Object.class, "_parentHandle$volatile");
    private volatile /* synthetic */ Object _parentHandle$volatile;
    private volatile /* synthetic */ Object _state$volatile;

    public q0(boolean z) {
        this._state$volatile = z ? E.j : E.i;
    }

    public static C5032p X(kotlinx.coroutines.internal.i iVar) {
        while (iVar.h()) {
            kotlinx.coroutines.internal.i iVarE = iVar.e();
            if (iVarE == null) {
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = kotlinx.coroutines.internal.i.b;
                Object obj = atomicReferenceFieldUpdater.get(iVar);
                while (true) {
                    iVar = (kotlinx.coroutines.internal.i) obj;
                    if (!iVar.h()) {
                        break;
                    }
                    obj = atomicReferenceFieldUpdater.get(iVar);
                }
            } else {
                iVar = iVarE;
            }
        }
        while (true) {
            iVar = iVar.g();
            if (!iVar.h()) {
                if (iVar instanceof C5032p) {
                    return (C5032p) iVar;
                }
                if (iVar instanceof t0) {
                    return null;
                }
            }
        }
    }

    public static String h0(Object obj) {
        if (!(obj instanceof o0)) {
            return obj instanceof InterfaceC4981e0 ? ((InterfaceC4981e0) obj).a() ? "Active" : "New" : obj instanceof C5036u ? "Cancelled" : "Completed";
        }
        o0 o0Var = (o0) obj;
        return o0Var.e() ? "Cancelling" : o0.b.get(o0Var) == 1 ? "Completing" : "Active";
    }

    public final boolean A(Throwable th) {
        if (T()) {
            return true;
        }
        boolean z = th instanceof CancellationException;
        InterfaceC5031o interfaceC5031o = (InterfaceC5031o) b.get(this);
        return (interfaceC5031o == null || interfaceC5031o == v0.a) ? z : interfaceC5031o.c(th) || z;
    }

    public String B() {
        return "Job was cancelled";
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final InterfaceC5031o C(q0 q0Var) {
        C5032p c5032p = new C5032p(q0Var);
        c5032p.d = this;
        loop0: while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = a;
            Object obj = atomicReferenceFieldUpdater.get(this);
            if (obj instanceof T) {
                T t = (T) obj;
                if (t.a) {
                    while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, c5032p)) {
                        if (atomicReferenceFieldUpdater.get(this) != obj) {
                            break;
                        }
                    }
                    break loop0;
                }
                e0(t);
            } else {
                boolean z = obj instanceof InterfaceC4981e0;
                v0 v0Var = v0.a;
                if (!z) {
                    Object obj2 = atomicReferenceFieldUpdater.get(this);
                    C5036u c5036u = obj2 instanceof C5036u ? (C5036u) obj2 : null;
                    c5032p.k(c5036u != null ? c5036u.a : null);
                    return v0Var;
                }
                t0 t0VarB = ((InterfaceC4981e0) obj).b();
                if (t0VarB == null) {
                    Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.JobNode");
                    f0((l0) obj);
                } else if (!t0VarB.d(c5032p, 7)) {
                    boolean zD = t0VarB.d(c5032p, 3);
                    Object obj3 = atomicReferenceFieldUpdater.get(this);
                    if (obj3 instanceof o0) {
                        thD = ((o0) obj3).d();
                    } else {
                        C5036u c5036u2 = obj3 instanceof C5036u ? (C5036u) obj3 : null;
                        if (c5036u2 != null) {
                            thD = c5036u2.a;
                        }
                    }
                    c5032p.k(thD);
                    if (zD) {
                        break loop0;
                    }
                    return v0Var;
                }
            }
        }
        return c5032p;
    }

    public boolean E(Throwable th) {
        if (th instanceof CancellationException) {
            return true;
        }
        return x(th) && K();
    }

    public final void F(InterfaceC4981e0 interfaceC4981e0, Object obj) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
        InterfaceC5031o interfaceC5031o = (InterfaceC5031o) atomicReferenceFieldUpdater.get(this);
        if (interfaceC5031o != null) {
            interfaceC5031o.dispose();
            atomicReferenceFieldUpdater.set(this, v0.a);
        }
        CompletionHandlerException completionHandlerException = null;
        C5036u c5036u = obj instanceof C5036u ? (C5036u) obj : null;
        Throwable th = c5036u != null ? c5036u.a : null;
        if (interfaceC4981e0 instanceof l0) {
            try {
                ((l0) interfaceC4981e0).k(th);
                return;
            } catch (Throwable th2) {
                O(new CompletionHandlerException("Exception in completion handler " + interfaceC4981e0 + " for " + this, th2));
                return;
            }
        }
        t0 t0VarB = interfaceC4981e0.b();
        if (t0VarB != null) {
            t0VarB.d(new kotlinx.coroutines.internal.h(1), 1);
            Object obj2 = kotlinx.coroutines.internal.i.a.get(t0VarB);
            Intrinsics.e(obj2, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode");
            for (kotlinx.coroutines.internal.i iVarG = (kotlinx.coroutines.internal.i) obj2; !iVarG.equals(t0VarB); iVarG = iVarG.g()) {
                if (iVarG instanceof l0) {
                    try {
                        ((l0) iVarG).k(th);
                    } catch (Throwable th3) {
                        if (completionHandlerException != null) {
                            C4937f.a(completionHandlerException, th3);
                        } else {
                            completionHandlerException = new CompletionHandlerException("Exception in completion handler " + iVarG + " for " + this, th3);
                            Unit unit = Unit.a;
                        }
                    }
                }
            }
            if (completionHandlerException != null) {
                O(completionHandlerException);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v11, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.lang.Throwable] */
    public final Throwable G(Object obj) {
        CancellationException cancellationExceptionD;
        if (obj instanceof Throwable) {
            return (Throwable) obj;
        }
        q0 q0Var = (q0) ((x0) obj);
        Object obj2 = a.get(q0Var);
        if (obj2 instanceof o0) {
            cancellationExceptionD = ((o0) obj2).d();
        } else if (obj2 instanceof C5036u) {
            cancellationExceptionD = ((C5036u) obj2).a;
        } else {
            if (obj2 instanceof InterfaceC4981e0) {
                throw new IllegalStateException(("Cannot be cancelling child in this state: " + obj2).toString());
            }
            cancellationExceptionD = null;
        }
        CancellationException cancellationException = cancellationExceptionD instanceof CancellationException ? cancellationExceptionD : null;
        return cancellationException == null ? new JobCancellationException("Parent job is ".concat(h0(obj2)), cancellationExceptionD, q0Var) : cancellationException;
    }

    public final Object H(o0 o0Var, Object obj) {
        Throwable thJ;
        C5036u c5036u = obj instanceof C5036u ? (C5036u) obj : null;
        Throwable th = c5036u != null ? c5036u.a : null;
        synchronized (o0Var) {
            o0Var.e();
            ArrayList<Throwable> arrayListF = o0Var.f(th);
            thJ = J(o0Var, arrayListF);
            if (thJ != null && arrayListF.size() > 1) {
                Set setNewSetFromMap = Collections.newSetFromMap(new IdentityHashMap(arrayListF.size()));
                for (Throwable th2 : arrayListF) {
                    if (th2 != thJ && th2 != thJ && !(th2 instanceof CancellationException) && setNewSetFromMap.add(th2)) {
                        C4937f.a(thJ, th2);
                    }
                }
            }
        }
        if (thJ != null && thJ != th) {
            obj = new C5036u(thJ, false);
        }
        if (thJ != null && (A(thJ) || N(thJ))) {
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.CompletedExceptionally");
            C5036u.b.compareAndSet((C5036u) obj, 0, 1);
        }
        b0(obj);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = a;
        Object c4983f0 = obj instanceof InterfaceC4981e0 ? new C4983f0((InterfaceC4981e0) obj) : obj;
        while (!atomicReferenceFieldUpdater.compareAndSet(this, o0Var, c4983f0) && atomicReferenceFieldUpdater.get(this) == o0Var) {
        }
        F(o0Var, obj);
        return obj;
    }

    public final Object I() throws Throwable {
        Object obj = a.get(this);
        if (obj instanceof InterfaceC4981e0) {
            throw new IllegalStateException("This job has not completed yet");
        }
        if (obj instanceof C5036u) {
            throw ((C5036u) obj).a;
        }
        return E.I(obj);
    }

    public final Throwable J(o0 o0Var, ArrayList arrayList) {
        Object next;
        Object obj = null;
        if (arrayList.isEmpty()) {
            if (o0Var.e()) {
                return new JobCancellationException(B(), null, this);
            }
            return null;
        }
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (!(((Throwable) next) instanceof CancellationException)) {
                break;
            }
        }
        Throwable th = (Throwable) next;
        if (th != null) {
            return th;
        }
        Throwable th2 = (Throwable) arrayList.get(0);
        if (th2 instanceof TimeoutCancellationException) {
            Iterator it3 = arrayList.iterator();
            while (true) {
                if (!it3.hasNext()) {
                    break;
                }
                Object next2 = it3.next();
                Throwable th3 = (Throwable) next2;
                if (th3 != th2 && (th3 instanceof TimeoutCancellationException)) {
                    obj = next2;
                    break;
                }
            }
            Throwable th4 = (Throwable) obj;
            if (th4 != null) {
                return th4;
            }
        }
        return th2;
    }

    public boolean K() {
        return true;
    }

    public boolean L() {
        return this instanceof r;
    }

    public final t0 M(InterfaceC4981e0 interfaceC4981e0) {
        t0 t0VarB = interfaceC4981e0.b();
        if (t0VarB != null) {
            return t0VarB;
        }
        if (interfaceC4981e0 instanceof T) {
            return new t0();
        }
        if (interfaceC4981e0 instanceof l0) {
            f0((l0) interfaceC4981e0);
            return null;
        }
        throw new IllegalStateException(("State should have list: " + interfaceC4981e0).toString());
    }

    public boolean N(Throwable th) {
        return false;
    }

    public void O(CompletionHandlerException completionHandlerException) {
        throw completionHandlerException;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Q Q(Function1 function1) {
        return S(true, new S(function1, 1));
    }

    public final void R(InterfaceC5025j0 interfaceC5025j0) {
        v0 v0Var = v0.a;
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
        if (interfaceC5025j0 == null) {
            atomicReferenceFieldUpdater.set(this, v0Var);
            return;
        }
        interfaceC5025j0.start();
        InterfaceC5031o interfaceC5031oC = interfaceC5025j0.C(this);
        atomicReferenceFieldUpdater.set(this, interfaceC5031oC);
        if (d0()) {
            interfaceC5031oC.dispose();
            atomicReferenceFieldUpdater.set(this, v0Var);
        }
    }

    public final Q S(boolean z, l0 l0Var) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        v0 v0Var;
        boolean z2;
        boolean zD;
        l0Var.d = this;
        loop0: while (true) {
            atomicReferenceFieldUpdater = a;
            Object obj = atomicReferenceFieldUpdater.get(this);
            boolean z3 = obj instanceof T;
            v0Var = v0.a;
            z2 = true;
            if (!z3) {
                if (!(obj instanceof InterfaceC4981e0)) {
                    z2 = false;
                    break;
                }
                InterfaceC4981e0 interfaceC4981e0 = (InterfaceC4981e0) obj;
                t0 t0VarB = interfaceC4981e0.b();
                if (t0VarB == null) {
                    Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.JobNode");
                    f0((l0) obj);
                } else {
                    if (l0Var.j()) {
                        o0 o0Var = interfaceC4981e0 instanceof o0 ? (o0) interfaceC4981e0 : null;
                        Throwable thD = o0Var != null ? o0Var.d() : null;
                        if (thD == null) {
                            zD = t0VarB.d(l0Var, 5);
                        } else if (z) {
                            l0Var.k(thD);
                            return v0Var;
                        }
                    } else {
                        zD = t0VarB.d(l0Var, 1);
                    }
                    if (zD) {
                        break;
                    }
                }
            } else {
                T t = (T) obj;
                if (t.a) {
                    while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, l0Var)) {
                        if (atomicReferenceFieldUpdater.get(this) != obj) {
                            break;
                        }
                    }
                    break loop0;
                }
                e0(t);
            }
        }
        if (z2) {
            return l0Var;
        }
        if (z) {
            Object obj2 = atomicReferenceFieldUpdater.get(this);
            C5036u c5036u = obj2 instanceof C5036u ? (C5036u) obj2 : null;
            l0Var.k(c5036u != null ? c5036u.a : null);
        }
        return v0Var;
    }

    public boolean T() {
        return this instanceof C5018g;
    }

    public final boolean U(Object obj) {
        Object objI0;
        do {
            objI0 = i0(a.get(this), obj);
            if (objI0 == E.d) {
                return false;
            }
            if (objI0 == E.e) {
                return true;
            }
        } while (objI0 == E.f);
        u(objI0);
        return true;
    }

    public final Object V(Object obj) {
        Object objI0;
        do {
            objI0 = i0(a.get(this), obj);
            if (objI0 == E.d) {
                String str = "Job " + this + " is already complete or completing, but is being completed with " + obj;
                C5036u c5036u = obj instanceof C5036u ? (C5036u) obj : null;
                throw new IllegalStateException(str, c5036u != null ? c5036u.a : null);
            }
        } while (objI0 == E.f);
        return objI0;
    }

    public String W() {
        return getClass().getSimpleName();
    }

    public final void Z(t0 t0Var, Throwable th) {
        t0Var.d(new kotlinx.coroutines.internal.h(4), 4);
        Object obj = kotlinx.coroutines.internal.i.a.get(t0Var);
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode");
        CompletionHandlerException completionHandlerException = null;
        for (kotlinx.coroutines.internal.i iVarG = (kotlinx.coroutines.internal.i) obj; !iVarG.equals(t0Var); iVarG = iVarG.g()) {
            if ((iVarG instanceof l0) && ((l0) iVarG).j()) {
                try {
                    ((l0) iVarG).k(th);
                } catch (Throwable th2) {
                    if (completionHandlerException != null) {
                        C4937f.a(completionHandlerException, th2);
                    } else {
                        completionHandlerException = new CompletionHandlerException("Exception in completion handler " + iVarG + " for " + this, th2);
                        Unit unit = Unit.a;
                    }
                }
            }
        }
        if (completionHandlerException != null) {
            O(completionHandlerException);
        }
        A(th);
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public boolean a() {
        Object obj = a.get(this);
        return (obj instanceof InterfaceC4981e0) && ((InterfaceC4981e0) obj).a();
    }

    public void a0(Throwable th) {
    }

    public void b0(Object obj) {
    }

    public void c0() {
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Sequence d() {
        p0 block = new p0(null, this);
        Intrinsics.checkNotNullParameter(block, "block");
        return new C4931w(block);
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean d0() {
        return !(a.get(this) instanceof InterfaceC4981e0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v3, types: [kotlinx.coroutines.d0] */
    public final void e0(T t) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        t0 t0Var = new t0();
        if (!t.a) {
            t0Var = new C4979d0(t0Var);
        }
        do {
            atomicReferenceFieldUpdater = a;
            if (atomicReferenceFieldUpdater.compareAndSet(this, t, t0Var)) {
                return;
            }
        } while (atomicReferenceFieldUpdater.get(this) == t);
    }

    public final void f0(l0 l0Var) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        t0 t0Var = new t0();
        l0Var.getClass();
        kotlinx.coroutines.internal.i.b.set(t0Var, l0Var);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = kotlinx.coroutines.internal.i.a;
        atomicReferenceFieldUpdater2.set(t0Var, l0Var);
        loop0: while (true) {
            if (atomicReferenceFieldUpdater2.get(l0Var) == l0Var) {
                while (!atomicReferenceFieldUpdater2.compareAndSet(l0Var, l0Var, t0Var)) {
                    if (atomicReferenceFieldUpdater2.get(l0Var) != l0Var) {
                        break;
                    }
                }
                t0Var.f(l0Var);
                break loop0;
            }
            break;
        }
        kotlinx.coroutines.internal.i iVarG = l0Var.g();
        do {
            atomicReferenceFieldUpdater = a;
            if (atomicReferenceFieldUpdater.compareAndSet(this, l0Var, iVarG)) {
                return;
            }
        } while (atomicReferenceFieldUpdater.get(this) == l0Var);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    public final int g0(Object obj) {
        boolean z = obj instanceof T;
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = a;
        if (z) {
            if (((T) obj).a) {
                return 0;
            }
            T t = E.j;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, t)) {
                if (atomicReferenceFieldUpdater.get(this) != obj) {
                    return -1;
                }
            }
            c0();
            return 1;
        }
        if (!(obj instanceof C4979d0)) {
            return 0;
        }
        t0 t0Var = ((C4979d0) obj).a;
        while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, t0Var)) {
            if (atomicReferenceFieldUpdater.get(this) != obj) {
                return -1;
            }
        }
        c0();
        return 1;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext.Element
    public final kotlin.coroutines.l getKey() {
        return C5023i0.a;
    }

    public final Object i0(Object obj, Object obj2) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        if (!(obj instanceof InterfaceC4981e0)) {
            return E.d;
        }
        if (((obj instanceof T) || (obj instanceof l0)) && !(obj instanceof C5032p) && !(obj2 instanceof C5036u)) {
            InterfaceC4981e0 interfaceC4981e0 = (InterfaceC4981e0) obj;
            Object c4983f0 = obj2 instanceof InterfaceC4981e0 ? new C4983f0((InterfaceC4981e0) obj2) : obj2;
            do {
                atomicReferenceFieldUpdater = a;
                if (atomicReferenceFieldUpdater.compareAndSet(this, interfaceC4981e0, c4983f0)) {
                    b0(obj2);
                    F(interfaceC4981e0, obj2);
                    return obj2;
                }
            } while (atomicReferenceFieldUpdater.get(this) == interfaceC4981e0);
            return E.f;
        }
        InterfaceC4981e0 interfaceC4981e02 = (InterfaceC4981e0) obj;
        t0 t0VarM = M(interfaceC4981e02);
        if (t0VarM == null) {
            return E.f;
        }
        o0 o0Var = interfaceC4981e02 instanceof o0 ? (o0) interfaceC4981e02 : null;
        if (o0Var == null) {
            o0Var = new o0(t0VarM, null);
        }
        synchronized (o0Var) {
            try {
                AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = o0.b;
                if (atomicIntegerFieldUpdater.get(o0Var) == 1) {
                    return E.d;
                }
                atomicIntegerFieldUpdater.set(o0Var, 1);
                if (o0Var != interfaceC4981e02) {
                    AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = a;
                    while (!atomicReferenceFieldUpdater2.compareAndSet(this, interfaceC4981e02, o0Var)) {
                        if (atomicReferenceFieldUpdater2.get(this) != interfaceC4981e02) {
                            return E.f;
                        }
                    }
                }
                boolean zE = o0Var.e();
                C5036u c5036u = obj2 instanceof C5036u ? (C5036u) obj2 : null;
                if (c5036u != null) {
                    o0Var.c(c5036u.a);
                }
                Throwable thD = zE ? null : o0Var.d();
                Unit unit = Unit.a;
                if (thD != null) {
                    Z(t0VarM, thD);
                }
                C5032p c5032pX = X(t0VarM);
                if (c5032pX != null && j0(o0Var, c5032pX, obj2)) {
                    return E.e;
                }
                t0VarM.d(new kotlinx.coroutines.internal.h(2), 2);
                C5032p c5032pX2 = X(t0VarM);
                return (c5032pX2 == null || !j0(o0Var, c5032pX2, obj2)) ? H(o0Var, obj2) : E.e;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean isCancelled() {
        Object obj = a.get(this);
        if (obj instanceof C5036u) {
            return true;
        }
        return (obj instanceof o0) && ((o0) obj).e();
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0, kotlinx.coroutines.channels.w
    public void j(CancellationException cancellationException) {
        if (cancellationException == null) {
            cancellationException = new JobCancellationException(B(), null, this);
        }
        z(cancellationException);
    }

    public final boolean j0(o0 o0Var, C5032p c5032p, Object obj) {
        while (E.v(c5032p.e, false, new n0(this, o0Var, c5032p, obj)) == v0.a) {
            c5032p = X(c5032p);
            if (c5032p == null) {
                return false;
            }
        }
        return true;
    }

    public Object l() {
        return I();
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Object p(kotlin.coroutines.jvm.internal.c frame) {
        Object obj;
        do {
            obj = a.get(this);
            if (!(obj instanceof InterfaceC4981e0)) {
                E.o(frame.getContext());
                return Unit.a;
            }
        } while (g0(obj) < 0);
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        c5028l.v(new C5022i(E.v(this, true, new C5030n(c5028l, 1)), 2));
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        if (objQ != aVar) {
            objQ = Unit.a;
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Q q(boolean z, boolean z2, Function1 function1) {
        return S(z2, z ? new C5021h0(function1) : new S(function1, 1));
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean start() {
        int iG0;
        do {
            iG0 = g0(a.get(this));
            if (iG0 == 0) {
                return false;
            }
        } while (iG0 != 1);
        return true;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(W() + '{' + h0(a.get(this)) + '}');
        sb.append('@');
        sb.append(E.r(this));
        return sb.toString();
    }

    public void u(Object obj) {
    }

    public void v(Object obj) {
        u(obj);
    }

    public final Object w(kotlin.coroutines.h frame) throws Throwable {
        Object obj;
        do {
            obj = a.get(this);
            if (!(obj instanceof InterfaceC4981e0)) {
                if (obj instanceof C5036u) {
                    throw ((C5036u) obj).a;
                }
                return E.I(obj);
            }
        } while (g0(obj) < 0);
        m0 m0Var = new m0(kotlin.coroutines.intrinsics.h.b(frame), this);
        m0Var.r();
        m0Var.v(new C5022i(E.v(this, true, new S(m0Var, 2)), 2));
        Object objQ = m0Var.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x006a, code lost:
    
        r0 = r10;
     */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0041 A[PHI: r0
  0x0041: PHI (r0v1 java.lang.Object) = (r0v0 java.lang.Object), (r0v13 java.lang.Object) binds: [B:3:0x0008, B:16:0x003d] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean x(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 275
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.q0.x(java.lang.Object):boolean");
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final CancellationException y() {
        CancellationException jobCancellationException;
        Object obj = a.get(this);
        if (!(obj instanceof o0)) {
            if (obj instanceof InterfaceC4981e0) {
                throw new IllegalStateException(("Job is still new or active: " + this).toString());
            }
            if (!(obj instanceof C5036u)) {
                return new JobCancellationException(getClass().getSimpleName().concat(" has completed normally"), null, this);
            }
            Throwable th = ((C5036u) obj).a;
            jobCancellationException = th instanceof CancellationException ? (CancellationException) th : null;
            return jobCancellationException == null ? new JobCancellationException(B(), th, this) : jobCancellationException;
        }
        Throwable thD = ((o0) obj).d();
        if (thD == null) {
            throw new IllegalStateException(("Job is still new or active: " + this).toString());
        }
        String strConcat = getClass().getSimpleName().concat(" is cancelling");
        jobCancellationException = thD instanceof CancellationException ? (CancellationException) thD : null;
        if (jobCancellationException == null) {
            if (strConcat == null) {
                strConcat = B();
            }
            jobCancellationException = new JobCancellationException(strConcat, thD, this);
        }
        return jobCancellationException;
    }

    public void z(CancellationException cancellationException) {
        x(cancellationException);
    }
}
