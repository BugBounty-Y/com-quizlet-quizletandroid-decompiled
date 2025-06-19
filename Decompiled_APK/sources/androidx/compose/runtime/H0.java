package androidx.compose.runtime;

import androidx.compose.material3.F2;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class H0 extends androidx.compose.runtime.snapshots.A implements androidx.compose.runtime.snapshots.o, InterfaceC0773a0, W0 {
    public G0 b;

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableIntStateImpl.IntStateStateRecord");
        this.b = (G0) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B b() {
        return this.b;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Object component1() {
        return Integer.valueOf(i());
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Function1 component2() {
        return new F2(this, 1);
    }

    @Override // androidx.compose.runtime.snapshots.o
    public final M0 d() {
        return V.f;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B g(androidx.compose.runtime.snapshots.B b, androidx.compose.runtime.snapshots.B b2, androidx.compose.runtime.snapshots.B b3) {
        if (((G0) b2).c == ((G0) b3).c) {
            return b2;
        }
        return null;
    }

    @Override // androidx.compose.runtime.W0
    public Object getValue() {
        return Integer.valueOf(i());
    }

    public final int i() {
        return ((G0) androidx.compose.runtime.snapshots.m.t(this.b, this)).c;
    }

    public final void j(int i) {
        androidx.compose.runtime.snapshots.h hVarK;
        G0 g0 = (G0) androidx.compose.runtime.snapshots.m.i(this.b);
        if (g0.c != i) {
            G0 g02 = this.b;
            synchronized (androidx.compose.runtime.snapshots.m.b) {
                hVarK = androidx.compose.runtime.snapshots.m.k();
                ((G0) androidx.compose.runtime.snapshots.m.o(g02, this, hVarK, g0)).c = i;
                Unit unit = Unit.a;
            }
            androidx.compose.runtime.snapshots.m.n(hVarK, this);
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public void setValue(Object obj) {
        j(((Number) obj).intValue());
    }

    public final String toString() {
        return "MutableIntState(value=" + ((G0) androidx.compose.runtime.snapshots.m.i(this.b)).c + ")@" + hashCode();
    }
}
