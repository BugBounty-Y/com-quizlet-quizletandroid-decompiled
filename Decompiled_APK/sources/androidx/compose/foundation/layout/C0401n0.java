package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0401n0 extends androidx.compose.ui.p implements androidx.compose.ui.node.j0 {
    public androidx.compose.ui.g n;

    @Override // androidx.compose.ui.node.j0
    public final Object U(androidx.compose.ui.unit.b bVar, Object obj) {
        D0 d0 = obj instanceof D0 ? (D0) obj : null;
        if (d0 == null) {
            d0 = new D0();
        }
        d0.c = new L(this.n);
        return d0;
    }
}
