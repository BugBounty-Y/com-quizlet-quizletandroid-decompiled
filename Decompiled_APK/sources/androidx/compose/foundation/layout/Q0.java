package androidx.compose.foundation.layout;

/* loaded from: classes.dex */
public final class Q0 extends androidx.compose.ui.p implements androidx.compose.ui.node.j0 {
    public androidx.compose.ui.h n;

    @Override // androidx.compose.ui.node.j0
    public final Object U(androidx.compose.ui.unit.b bVar, Object obj) {
        D0 d0 = obj instanceof D0 ? (D0) obj : null;
        if (d0 == null) {
            d0 = new D0();
        }
        d0.c = new M(this.n);
        return d0;
    }
}
