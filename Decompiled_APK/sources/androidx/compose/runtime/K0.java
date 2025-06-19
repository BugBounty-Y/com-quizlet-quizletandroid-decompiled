package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K0 extends androidx.compose.runtime.snapshots.B {
    public Object c;

    public K0(long j, Object obj) {
        super(j);
        this.c = obj;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableStateImpl.StateStateRecord<T of androidx.compose.runtime.SnapshotMutableStateImpl.StateStateRecord>");
        this.c = ((K0) b).c;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final androidx.compose.runtime.snapshots.B b(long j) {
        return new K0(androidx.compose.runtime.snapshots.m.k().g(), this.c);
    }
}
