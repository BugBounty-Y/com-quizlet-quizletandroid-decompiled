package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class F0 extends androidx.compose.runtime.snapshots.A implements androidx.compose.runtime.snapshots.o, InterfaceC0773a0, W0 {
    public E0 b;

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableFloatStateImpl.FloatStateStateRecord");
        this.b = (E0) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B b() {
        return this.b;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Object component1() {
        return Float.valueOf(i());
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Function1 component2() {
        return new C0775b0(this, 3);
    }

    @Override // androidx.compose.runtime.snapshots.o
    public final M0 d() {
        return V.f;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B g(androidx.compose.runtime.snapshots.B b, androidx.compose.runtime.snapshots.B b2, androidx.compose.runtime.snapshots.B b3) {
        if (((E0) b2).c == ((E0) b3).c) {
            return b2;
        }
        return null;
    }

    @Override // androidx.compose.runtime.W0
    public Object getValue() {
        return Float.valueOf(i());
    }

    public final float i() {
        return ((E0) androidx.compose.runtime.snapshots.m.t(this.b, this)).c;
    }

    public final void j(float f) {
        androidx.compose.runtime.snapshots.h hVarK;
        E0 e0 = (E0) androidx.compose.runtime.snapshots.m.i(this.b);
        if (e0.c == f) {
            return;
        }
        E0 e02 = this.b;
        synchronized (androidx.compose.runtime.snapshots.m.b) {
            hVarK = androidx.compose.runtime.snapshots.m.k();
            ((E0) androidx.compose.runtime.snapshots.m.o(e02, this, hVarK, e0)).c = f;
            Unit unit = Unit.a;
        }
        androidx.compose.runtime.snapshots.m.n(hVarK, this);
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public void setValue(Object obj) {
        j(((Number) obj).floatValue());
    }

    public final String toString() {
        return "MutableFloatState(value=" + ((E0) androidx.compose.runtime.snapshots.m.i(this.b)).c + ")@" + hashCode();
    }
}
