package androidx.compose.material3;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.InterfaceC0926w;

/* loaded from: classes.dex */
public final class Y1 extends androidx.compose.ui.p implements InterfaceC0916l, InterfaceC0926w {
    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        float f = ((androidx.compose.ui.unit.e) AbstractC0910f.i(this, F1.a)).a;
        float f2 = 0;
        if (f < f2) {
            f = f2;
        }
        androidx.compose.ui.layout.W wB = j.B(j2);
        boolean z = this.m && !Float.isNaN(f) && Float.compare(f, f2) > 0;
        int iM0 = Float.isNaN(f) ? 0 : m.m0(f);
        int iMax = z ? Math.max(wB.a, iM0) : wB.a;
        int iMax2 = z ? Math.max(wB.b, iM0) : wB.b;
        return m.n0(iMax, iMax2, kotlin.collections.V.c(), new androidx.compose.foundation.O0(iMax, wB, iMax2));
    }
}
