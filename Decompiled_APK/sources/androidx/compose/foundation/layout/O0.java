package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class O0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;
    public float o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        int iZ = j.z(i);
        int iM0 = !androidx.compose.ui.unit.e.a(this.n, Float.NaN) ? o.m0(this.n) : 0;
        return iZ < iM0 ? iM0 : iZ;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        int iX = j.x(i);
        int iM0 = !androidx.compose.ui.unit.e.a(this.n, Float.NaN) ? o.m0(this.n) : 0;
        return iX < iM0 ? iM0 : iX;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        int iX = j.X(i);
        int iM0 = !androidx.compose.ui.unit.e.a(this.o, Float.NaN) ? o.m0(this.o) : 0;
        return iX < iM0 ? iM0 : iX;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        int iJ;
        int i = 0;
        if (androidx.compose.ui.unit.e.a(this.n, Float.NaN) || androidx.compose.ui.unit.a.j(j2) != 0) {
            iJ = androidx.compose.ui.unit.a.j(j2);
        } else {
            iJ = m.m0(this.n);
            int iH = androidx.compose.ui.unit.a.h(j2);
            if (iJ > iH) {
                iJ = iH;
            }
            if (iJ < 0) {
                iJ = 0;
            }
        }
        int iH2 = androidx.compose.ui.unit.a.h(j2);
        if (androidx.compose.ui.unit.e.a(this.o, Float.NaN) || androidx.compose.ui.unit.a.i(j2) != 0) {
            i = androidx.compose.ui.unit.a.i(j2);
        } else {
            int iM0 = m.m0(this.o);
            int iG = androidx.compose.ui.unit.a.g(j2);
            if (iM0 > iG) {
                iM0 = iG;
            }
            if (iM0 >= 0) {
                i = iM0;
            }
        }
        androidx.compose.ui.layout.W wB = j.B(L5.a(iJ, iH2, i, androidx.compose.ui.unit.a.g(j2)));
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 8));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        int iB = j.b(i);
        int iM0 = !androidx.compose.ui.unit.e.a(this.o, Float.NaN) ? o.m0(this.o) : 0;
        return iB < iM0 ? iM0 : iB;
    }
}
