package androidx.compose.runtime.snapshots;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p extends B {
    public androidx.compose.runtime.external.kotlinx.collections.immutable.c c;
    public int d;
    public int e;

    public p(long j, androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar) {
        super(j);
        this.c = cVar;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(B b) {
        synchronized (r.a) {
            Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord>");
            this.c = ((p) b).c;
            this.d = ((p) b).d;
            this.e = ((p) b).e;
            Unit unit = Unit.a;
        }
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final B b(long j) {
        return new p(j, this.c);
    }
}
