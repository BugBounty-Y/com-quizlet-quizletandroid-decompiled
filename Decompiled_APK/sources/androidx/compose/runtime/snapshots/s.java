package androidx.compose.runtime.snapshots;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s extends B {
    public androidx.compose.runtime.external.kotlinx.collections.immutable.e c;
    public int d;

    public s(long j, androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar) {
        super(j);
        this.c = eVar;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord, V of androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord>");
        s sVar = (s) b;
        synchronized (r.b) {
            this.c = sVar.c;
            this.d = sVar.d;
            Unit unit = Unit.a;
        }
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final B b(long j) {
        return new s(j, this.c);
    }
}
