package androidx.compose.foundation.layout;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* renamed from: androidx.compose.foundation.layout.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0400n extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;

    public final long M0(long j, boolean z) {
        int iRound;
        int iG = androidx.compose.ui.unit.a.g(j);
        if (iG == Integer.MAX_VALUE || (iRound = Math.round(iG * this.n)) <= 0) {
            return 0L;
        }
        long jA = R5.a(iRound, iG);
        if (!z || L5.n(j, jA)) {
            return jA;
        }
        return 0L;
    }

    public final long N0(long j, boolean z) {
        int iRound;
        int iH = androidx.compose.ui.unit.a.h(j);
        if (iH == Integer.MAX_VALUE || (iRound = Math.round(iH / this.n)) <= 0) {
            return 0L;
        }
        long jA = R5.a(iH, iRound);
        if (!z || L5.n(j, jA)) {
            return jA;
        }
        return 0L;
    }

    public final long O0(long j, boolean z) {
        int i = androidx.compose.ui.unit.a.i(j);
        int iRound = Math.round(i * this.n);
        if (iRound <= 0) {
            return 0L;
        }
        long jA = R5.a(iRound, i);
        if (!z || L5.n(j, jA)) {
            return jA;
        }
        return 0L;
    }

    public final long P0(long j, boolean z) {
        int iJ = androidx.compose.ui.unit.a.j(j);
        int iRound = Math.round(iJ / this.n);
        if (iRound <= 0) {
            return 0L;
        }
        long jA = R5.a(iJ, iRound);
        if (!z || L5.n(j, jA)) {
            return jA;
        }
        return 0L;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return i != Integer.MAX_VALUE ? Math.round(i * this.n) : j.z(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return i != Integer.MAX_VALUE ? Math.round(i * this.n) : j.x(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return i != Integer.MAX_VALUE ? Math.round(i / this.n) : j.X(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        long jN0 = N0(j2, true);
        if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
            jN0 = M0(j2, true);
            if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                jN0 = P0(j2, true);
                if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                    jN0 = O0(j2, true);
                    if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                        jN0 = N0(j2, false);
                        if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                            jN0 = M0(j2, false);
                            if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                                jN0 = P0(j2, false);
                                if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                                    jN0 = O0(j2, false);
                                    if (androidx.compose.ui.unit.j.a(jN0, 0L)) {
                                        jN0 = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!androidx.compose.ui.unit.j.a(jN0, 0L)) {
            int i = (int) (jN0 >> 32);
            int i2 = (int) (jN0 & 4294967295L);
            if (i < 0 || i2 < 0) {
                O5.e("width(" + i + ") and height(" + i2 + ") must be >= 0");
                throw null;
            }
            j2 = L5.m(i, i, i2, i2);
        }
        androidx.compose.ui.layout.W wB = j.B(j2);
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 3));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return i != Integer.MAX_VALUE ? Math.round(i / this.n) : j.b(i);
    }
}
