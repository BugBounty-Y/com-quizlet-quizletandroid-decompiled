package kotlinx.coroutines;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class l0 extends kotlinx.coroutines.internal.i implements Q, InterfaceC4981e0 {
    public q0 d;

    @Override // kotlinx.coroutines.InterfaceC4981e0
    public final boolean a() {
        return true;
    }

    @Override // kotlinx.coroutines.InterfaceC4981e0
    public final t0 b() {
        return null;
    }

    @Override // kotlinx.coroutines.Q
    public final void dispose() {
        q0 q0VarI = i();
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = q0.a;
            Object obj = atomicReferenceFieldUpdater.get(q0VarI);
            if (obj instanceof l0) {
                if (obj != this) {
                    return;
                }
                T t = E.j;
                while (!atomicReferenceFieldUpdater.compareAndSet(q0VarI, obj, t)) {
                    if (atomicReferenceFieldUpdater.get(q0VarI) != obj) {
                        break;
                    }
                }
                return;
            }
            if (!(obj instanceof InterfaceC4981e0) || ((InterfaceC4981e0) obj).b() == null) {
                return;
            }
            while (true) {
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = kotlinx.coroutines.internal.i.a;
                Object obj2 = atomicReferenceFieldUpdater2.get(this);
                if (obj2 instanceof kotlinx.coroutines.internal.n) {
                    kotlinx.coroutines.internal.i iVar = ((kotlinx.coroutines.internal.n) obj2).a;
                    return;
                }
                if (obj2 == this) {
                    return;
                }
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode");
                kotlinx.coroutines.internal.i iVar2 = (kotlinx.coroutines.internal.i) obj2;
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater3 = kotlinx.coroutines.internal.i.c;
                kotlinx.coroutines.internal.n nVar = (kotlinx.coroutines.internal.n) atomicReferenceFieldUpdater3.get(iVar2);
                if (nVar == null) {
                    nVar = new kotlinx.coroutines.internal.n(iVar2);
                    atomicReferenceFieldUpdater3.set(iVar2, nVar);
                }
                while (!atomicReferenceFieldUpdater2.compareAndSet(this, obj2, nVar)) {
                    if (atomicReferenceFieldUpdater2.get(this) != obj2) {
                        break;
                    }
                }
                iVar2.e();
                return;
            }
        }
    }

    public InterfaceC5025j0 getParent() {
        return i();
    }

    public final q0 i() {
        q0 q0Var = this.d;
        if (q0Var != null) {
            return q0Var;
        }
        Intrinsics.m("job");
        throw null;
    }

    public abstract boolean j();

    public abstract void k(Throwable th);

    @Override // kotlinx.coroutines.internal.i
    public final String toString() {
        return getClass().getSimpleName() + '@' + E.r(this) + "[job@" + E.r(i()) + ']';
    }
}
