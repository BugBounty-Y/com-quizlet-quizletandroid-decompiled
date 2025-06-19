package androidx.compose.foundation;

import androidx.compose.ui.node.AbstractC0910f;

/* loaded from: classes.dex */
public final class Z extends androidx.compose.ui.p implements androidx.compose.ui.node.q0 {
    public static final z0 o = new z0(6);
    public androidx.camera.lifecycle.f n;

    public final void M0(androidx.compose.ui.layout.r rVar) {
        this.n.invoke(rVar);
        Z z = (Z) AbstractC0910f.k(this);
        if (z != null) {
            z.M0(rVar);
        }
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return o;
    }
}
