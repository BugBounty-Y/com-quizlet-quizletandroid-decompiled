package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class P extends androidx.compose.ui.p implements InterfaceC0926w {
    public int n;
    public float o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        int iJ;
        int iH;
        int iG;
        int iC;
        if (!androidx.compose.ui.unit.a.d(j2) || this.n == 1) {
            iJ = androidx.compose.ui.unit.a.j(j2);
            iH = androidx.compose.ui.unit.a.h(j2);
        } else {
            iJ = kotlin.ranges.l.c(Math.round(androidx.compose.ui.unit.a.h(j2) * this.o), androidx.compose.ui.unit.a.j(j2), androidx.compose.ui.unit.a.h(j2));
            iH = iJ;
        }
        if (!androidx.compose.ui.unit.a.c(j2) || this.n == 2) {
            int i = androidx.compose.ui.unit.a.i(j2);
            iG = androidx.compose.ui.unit.a.g(j2);
            iC = i;
        } else {
            iC = kotlin.ranges.l.c(Math.round(androidx.compose.ui.unit.a.g(j2) * this.o), androidx.compose.ui.unit.a.i(j2), androidx.compose.ui.unit.a.g(j2));
            iG = iC;
        }
        androidx.compose.ui.layout.W wB = j.B(L5.a(iJ, iH, iC, iG));
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 5));
    }
}
