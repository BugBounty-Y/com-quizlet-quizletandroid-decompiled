package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class y0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;
    public float o;
    public float p;
    public float q;
    public boolean r;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        int iM0 = m.m0(this.p) + m.m0(this.n);
        int iM02 = m.m0(this.q) + m.m0(this.o);
        androidx.compose.ui.layout.W wB = j.B(L5.o(-iM0, -iM02, j2));
        return m.n0(L5.l(wB.a + iM0, j2), L5.k(wB.b + iM02, j2), kotlin.collections.V.c(), new androidx.activity.compose.g(this, wB, m, 8));
    }
}
