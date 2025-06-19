package androidx.compose.runtime;

import androidx.compose.runtime.snapshots.C0823c;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class L0 extends androidx.compose.runtime.snapshots.A implements androidx.compose.runtime.snapshots.o {
    public final M0 b;
    public K0 c;

    public L0(Object obj, M0 m0) {
        this.b = m0;
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        K0 k0 = new K0(hVarK.g(), obj);
        if (!(hVarK instanceof C0823c)) {
            k0.b = new K0(1, obj);
        }
        this.c = k0;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableStateImpl.StateStateRecord<T of androidx.compose.runtime.SnapshotMutableStateImpl>");
        this.c = (K0) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B b() {
        return this.c;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Object component1() {
        return getValue();
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Function1 component2() {
        return new C0775b0(this, 5);
    }

    @Override // androidx.compose.runtime.snapshots.o
    public final M0 d() {
        return this.b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B g(androidx.compose.runtime.snapshots.B b, androidx.compose.runtime.snapshots.B b2, androidx.compose.runtime.snapshots.B b3) {
        if (this.b.a(((K0) b2).c, ((K0) b3).c)) {
            return b2;
        }
        return null;
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return ((K0) androidx.compose.runtime.snapshots.m.t(this.c, this)).c;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final void setValue(Object obj) {
        androidx.compose.runtime.snapshots.h hVarK;
        K0 k0 = (K0) androidx.compose.runtime.snapshots.m.i(this.c);
        if (this.b.a(k0.c, obj)) {
            return;
        }
        K0 k02 = this.c;
        synchronized (androidx.compose.runtime.snapshots.m.b) {
            hVarK = androidx.compose.runtime.snapshots.m.k();
            ((K0) androidx.compose.runtime.snapshots.m.o(k02, this, hVarK, k0)).c = obj;
            Unit unit = Unit.a;
        }
        androidx.compose.runtime.snapshots.m.n(hVarK, this);
    }

    public final String toString() {
        return "MutableState(value=" + ((K0) androidx.compose.runtime.snapshots.m.i(this.c)).c + ")@" + hashCode();
    }
}
