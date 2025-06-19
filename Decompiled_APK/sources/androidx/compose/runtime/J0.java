package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class J0 extends androidx.compose.runtime.snapshots.A implements androidx.compose.runtime.snapshots.o, InterfaceC0773a0, W0 {
    public I0 b;

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableLongStateImpl.LongStateStateRecord");
        this.b = (I0) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B b() {
        return this.b;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Object component1() {
        return Long.valueOf(i());
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Function1 component2() {
        return new C0775b0(this, 4);
    }

    @Override // androidx.compose.runtime.snapshots.o
    public final M0 d() {
        return V.f;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B g(androidx.compose.runtime.snapshots.B b, androidx.compose.runtime.snapshots.B b2, androidx.compose.runtime.snapshots.B b3) {
        if (((I0) b2).c == ((I0) b3).c) {
            return b2;
        }
        return null;
    }

    @Override // androidx.compose.runtime.W0
    public Object getValue() {
        return Long.valueOf(i());
    }

    public final long i() {
        return ((I0) androidx.compose.runtime.snapshots.m.t(this.b, this)).c;
    }

    public final void j(long j) {
        androidx.compose.runtime.snapshots.h hVarK;
        I0 i0 = (I0) androidx.compose.runtime.snapshots.m.i(this.b);
        if (i0.c != j) {
            I0 i02 = this.b;
            synchronized (androidx.compose.runtime.snapshots.m.b) {
                hVarK = androidx.compose.runtime.snapshots.m.k();
                ((I0) androidx.compose.runtime.snapshots.m.o(i02, this, hVarK, i0)).c = j;
                Unit unit = Unit.a;
            }
            androidx.compose.runtime.snapshots.m.n(hVarK, this);
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public void setValue(Object obj) {
        j(((Number) obj).longValue());
    }

    public final String toString() {
        return "MutableLongState(value=" + ((I0) androidx.compose.runtime.snapshots.m.i(this.b)).c + ")@" + hashCode();
    }
}
