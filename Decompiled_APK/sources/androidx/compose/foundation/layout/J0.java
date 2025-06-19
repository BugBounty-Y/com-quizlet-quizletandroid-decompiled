package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.C0893n;

/* loaded from: classes.dex */
public final class J0 extends androidx.compose.ui.p implements androidx.compose.ui.node.j0 {
    public C0893n n;

    @Override // androidx.compose.ui.node.j0
    public final Object U(androidx.compose.ui.unit.b bVar, Object obj) {
        D0 d0 = obj instanceof D0 ? (D0) obj : null;
        if (d0 == null) {
            d0 = new D0();
        }
        d0.c = new K(new C0376b(this.n));
        return d0;
    }
}
