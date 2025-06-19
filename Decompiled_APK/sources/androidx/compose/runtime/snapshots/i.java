package androidx.compose.runtime.snapshots;

/* loaded from: classes.dex */
public final class i extends r {
    public final C0824d c;

    public i(C0824d c0824d) {
        this.c = c0824d;
    }

    @Override // androidx.compose.runtime.snapshots.r
    public final void c() throws SnapshotApplyConflictException {
        this.c.c();
        throw new SnapshotApplyConflictException();
    }
}
