package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class B0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public z0 n;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        float f = 0;
        if (Float.compare(this.n.b(m.getLayoutDirection()), f) < 0 || Float.compare(this.n.d(), f) < 0 || Float.compare(this.n.c(m.getLayoutDirection()), f) < 0 || Float.compare(this.n.a(), f) < 0) {
            throw new IllegalArgumentException("Padding must be non-negative");
        }
        int iM0 = m.m0(this.n.c(m.getLayoutDirection())) + m.m0(this.n.b(m.getLayoutDirection()));
        int iM02 = m.m0(this.n.a()) + m.m0(this.n.d());
        androidx.compose.ui.layout.W wB = j.B(L5.o(-iM0, -iM02, j2));
        return m.n0(L5.l(wB.a + iM0, j2), L5.k(wB.b + iM02, j2), kotlin.collections.V.c(), new androidx.activity.compose.g(wB, m, this, 9));
    }
}
