package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I0 extends androidx.compose.runtime.snapshots.B {
    public long c;

    public I0(long j, long j2) {
        super(j);
        this.c = j2;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableLongStateImpl.LongStateStateRecord");
        this.c = ((I0) b).c;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final androidx.compose.runtime.snapshots.B b(long j) {
        return new I0(j, this.c);
    }
}
