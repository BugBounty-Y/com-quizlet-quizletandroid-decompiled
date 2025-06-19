package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E0 extends androidx.compose.runtime.snapshots.B {
    public float c;

    public E0(long j, float f) {
        super(j);
        this.c = f;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableFloatStateImpl.FloatStateStateRecord");
        this.c = ((E0) b).c;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final androidx.compose.runtime.snapshots.B b(long j) {
        return new E0(j, this.c);
    }
}
