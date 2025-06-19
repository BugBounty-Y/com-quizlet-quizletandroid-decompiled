package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class V0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public int n;
    public kotlin.jvm.internal.r o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(L5.a(this.n != 1 ? 0 : androidx.compose.ui.unit.a.j(j2), androidx.compose.ui.unit.a.h(j2), this.n == 2 ? androidx.compose.ui.unit.a.i(j2) : 0, androidx.compose.ui.unit.a.g(j2)));
        int iC = kotlin.ranges.l.c(wB.a, androidx.compose.ui.unit.a.j(j2), androidx.compose.ui.unit.a.h(j2));
        int iC2 = kotlin.ranges.l.c(wB.b, androidx.compose.ui.unit.a.i(j2), androidx.compose.ui.unit.a.g(j2));
        return m.n0(iC, iC2, kotlin.collections.V.c(), new F0(this, iC, wB, iC2, m));
    }
}
