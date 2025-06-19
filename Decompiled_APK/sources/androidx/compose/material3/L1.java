package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0900v;
import androidx.compose.ui.layout.InterfaceC0894o;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import java.util.List;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class L1 {
    public static final float a = 8;
    public static final float b = 12;
    public static final float c;
    public static final float d;
    public static final float e;

    static {
        float f = 16;
        c = f;
        d = f;
        e = f;
    }

    public static final void a(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, G1 g1, float f, float f2, InterfaceC0806l interfaceC0806l, int i) {
        float f3;
        float f4;
        float f5;
        float f6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1647707763);
        if (((i | (c0814p.f(qVar) ? 32 : 16) | 28032 | (c0814p.h(dVar2) ? 131072 : 65536) | (c0814p.f(g1) ? 1048576 : 524288) | 113246208) & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
            f5 = f;
            f6 = f2;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                f3 = H1.a;
                f4 = f3;
            } else {
                c0814p.Q();
                f3 = f;
                f4 = f2;
            }
            c0814p.q();
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-403249643, new androidx.compose.foundation.contextmenu.i(14, g1, dVar), c0814p);
            c0814p.X(1640970492);
            c0814p.p(false);
            c0814p.X(1640980724);
            c0814p.p(false);
            c0814p.X(1640990750);
            c0814p.p(false);
            c0814p.X(1641004177);
            androidx.compose.runtime.internal.d dVar3 = null;
            androidx.compose.runtime.internal.d dVarE2 = dVar2 == null ? null : androidx.compose.runtime.internal.e.e(1512306332, new androidx.compose.foundation.contextmenu.i(15, g1, dVar2), c0814p);
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.semantics.m.a(androidx.compose.ui.n.b, true, C0736u.o).g(qVar);
            float f7 = H1.a;
            AbstractC0594b4.a(qVarG, B3.a(c0814p, androidx.compose.material3.tokens.n.j), g1.a, g1.b, f3, f4, null, androidx.compose.runtime.internal.e.e(1502590376, new C0722t0(dVar3, dVarE2, dVarE, dVar3, dVar3, 1), c0814p), c0814p, 12804096, 64);
            f5 = f3;
            f6 = f4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new I1(dVar, qVar, dVar2, g1, f5, f6, i);
        }
    }

    public static final void b(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3 = 0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2052297037);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar4) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(dVar5) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new Q1();
                c0814p.i0(objI);
            }
            Q1 q1 = (Q1) objI;
            List listJ = kotlin.collections.B.j(dVar3, dVar4 == null ? AbstractC0626h0.a : dVar4, dVar5 == null ? AbstractC0626h0.b : dVar5, dVar == null ? AbstractC0626h0.c : dVar, dVar2 == null ? AbstractC0626h0.d : dVar2);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.internal.d dVar6 = new androidx.compose.runtime.internal.d(true, -1953651383, new C0900v(listJ, i3));
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new androidx.compose.ui.layout.O(q1);
                c0814p.i0(objI2);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI2;
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w(0, dVar6, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.K(dVar, dVar2, dVar3, dVar4, dVar5, i);
        }
    }

    public static final void c(long j, androidx.compose.material3.tokens.G g, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1133967795);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(g) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0646j.a(j, Z4.a(g, c0814p), function2, c0814p, i2 & 910);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new J1(j, g, function2, i, 0);
        }
    }

    public static final int d(InterfaceC0894o interfaceC0894o, int i, int i2, int i3, int i4, int i5, int i6, int i7, long j) {
        int iMax = Math.max(Math.max(androidx.compose.ui.unit.a.i(j), interfaceC0894o.m0(i6 == 1 ? androidx.compose.material3.tokens.n.f : i6 == 2 ? androidx.compose.material3.tokens.n.i : androidx.compose.material3.tokens.n.g)), Math.max(i, Math.max(i3 + i4 + i5, i2)) + i7);
        int iG = androidx.compose.ui.unit.a.g(j);
        return iMax > iG ? iG : iMax;
    }
}
