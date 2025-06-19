package androidx.compose.foundation.lazy;

import androidx.compose.runtime.H0;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.collections.V;

/* loaded from: classes.dex */
public final class E extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;
    public H0 o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final L h(M m, J j, long j2) {
        H0 h0 = this.o;
        int iRound = (h0 == null || ((Number) h0.getValue()).intValue() == Integer.MAX_VALUE) ? Integer.MAX_VALUE : Math.round(((Number) h0.getValue()).floatValue() * this.n);
        int iJ = iRound != Integer.MAX_VALUE ? iRound : androidx.compose.ui.unit.a.j(j2);
        int i = androidx.compose.ui.unit.a.i(j2);
        if (iRound == Integer.MAX_VALUE) {
            iRound = androidx.compose.ui.unit.a.h(j2);
        }
        W wB = j.B(L5.a(iJ, iRound, i, androidx.compose.ui.unit.a.g(j2)));
        return m.n0(wB.a, wB.b, V.c(), new androidx.compose.animation.C(wB, 9));
    }
}
