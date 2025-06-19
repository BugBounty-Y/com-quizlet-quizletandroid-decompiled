package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class L0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;
    public float o;
    public float p;
    public float q;
    public boolean r;

    /* JADX WARN: Removed duplicated region for block: B:23:0x0043  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long M0(androidx.compose.ui.layout.InterfaceC0894o r8) {
        /*
            r7 = this;
            float r0 = r7.p
            r1 = 2143289344(0x7fc00000, float:NaN)
            boolean r0 = androidx.compose.ui.unit.e.a(r0, r1)
            r2 = 2147483647(0x7fffffff, float:NaN)
            r3 = 0
            if (r0 != 0) goto L18
            float r0 = r7.p
            int r0 = r8.m0(r0)
            if (r0 >= 0) goto L19
            r0 = r3
            goto L19
        L18:
            r0 = r2
        L19:
            float r4 = r7.q
            boolean r4 = androidx.compose.ui.unit.e.a(r4, r1)
            if (r4 != 0) goto L2b
            float r4 = r7.q
            int r4 = r8.m0(r4)
            if (r4 >= 0) goto L2c
            r4 = r3
            goto L2c
        L2b:
            r4 = r2
        L2c:
            float r5 = r7.n
            boolean r5 = androidx.compose.ui.unit.e.a(r5, r1)
            if (r5 != 0) goto L43
            float r5 = r7.n
            int r5 = r8.m0(r5)
            if (r5 <= r0) goto L3d
            r5 = r0
        L3d:
            if (r5 >= 0) goto L40
            r5 = r3
        L40:
            if (r5 == r2) goto L43
            goto L44
        L43:
            r5 = r3
        L44:
            float r6 = r7.o
            boolean r1 = androidx.compose.ui.unit.e.a(r6, r1)
            if (r1 != 0) goto L5b
            float r1 = r7.o
            int r8 = r8.m0(r1)
            if (r8 <= r4) goto L55
            r8 = r4
        L55:
            if (r8 >= 0) goto L58
            r8 = r3
        L58:
            if (r8 == r2) goto L5b
            r3 = r8
        L5b:
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.L5.a(r5, r0, r3, r4)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.layout.L0.M0(androidx.compose.ui.layout.o):long");
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        long jM0 = M0(o);
        return androidx.compose.ui.unit.a.f(jM0) ? androidx.compose.ui.unit.a.h(jM0) : L5.l(j.z(i), jM0);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        long jM0 = M0(o);
        return androidx.compose.ui.unit.a.f(jM0) ? androidx.compose.ui.unit.a.h(jM0) : L5.l(j.x(i), jM0);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        long jM0 = M0(o);
        return androidx.compose.ui.unit.a.e(jM0) ? androidx.compose.ui.unit.a.g(jM0) : L5.k(j.X(i), jM0);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        int iJ;
        int iH;
        int i;
        int iG;
        long jA;
        long jM0 = M0(m);
        if (this.r) {
            jA = L5.j(j2, jM0);
        } else {
            if (androidx.compose.ui.unit.e.a(this.n, Float.NaN)) {
                iJ = androidx.compose.ui.unit.a.j(j2);
                int iH2 = androidx.compose.ui.unit.a.h(jM0);
                if (iJ > iH2) {
                    iJ = iH2;
                }
            } else {
                iJ = androidx.compose.ui.unit.a.j(jM0);
            }
            if (androidx.compose.ui.unit.e.a(this.p, Float.NaN)) {
                iH = androidx.compose.ui.unit.a.h(j2);
                int iJ2 = androidx.compose.ui.unit.a.j(jM0);
                if (iH < iJ2) {
                    iH = iJ2;
                }
            } else {
                iH = androidx.compose.ui.unit.a.h(jM0);
            }
            if (androidx.compose.ui.unit.e.a(this.o, Float.NaN)) {
                i = androidx.compose.ui.unit.a.i(j2);
                int iG2 = androidx.compose.ui.unit.a.g(jM0);
                if (i > iG2) {
                    i = iG2;
                }
            } else {
                i = androidx.compose.ui.unit.a.i(jM0);
            }
            if (androidx.compose.ui.unit.e.a(this.q, Float.NaN)) {
                iG = androidx.compose.ui.unit.a.g(j2);
                int i2 = androidx.compose.ui.unit.a.i(jM0);
                if (iG < i2) {
                    iG = i2;
                }
            } else {
                iG = androidx.compose.ui.unit.a.g(jM0);
            }
            jA = L5.a(iJ, iH, i, iG);
        }
        androidx.compose.ui.layout.W wB = j.B(jA);
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 7));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        long jM0 = M0(o);
        return androidx.compose.ui.unit.a.e(jM0) ? androidx.compose.ui.unit.a.g(jM0) : L5.k(j.b(i), jM0);
    }
}
