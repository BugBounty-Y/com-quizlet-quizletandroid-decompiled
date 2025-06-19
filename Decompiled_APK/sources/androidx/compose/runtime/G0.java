package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G0 extends androidx.compose.runtime.snapshots.B {
    public int c;

    public G0(int i, long j) {
        super(j);
        this.c = i;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableIntStateImpl.IntStateStateRecord");
        this.c = ((G0) b).c;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final androidx.compose.runtime.snapshots.B b(long j) {
        return new G0(this.c, j);
    }
}
