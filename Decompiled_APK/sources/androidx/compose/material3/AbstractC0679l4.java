package androidx.compose.material3;

import androidx.compose.animation.core.C0249j0;
import androidx.compose.foundation.AbstractC0455m0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.l4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0679l4 {
    public static final float a;
    public static final float b;
    public static final float c;
    public static final float d;
    public static final float e;
    public static final C0249j0 f;
    public static final androidx.compose.animation.core.K0 g;

    static {
        float f2 = androidx.compose.material3.tokens.A.b;
        a = f2;
        b = androidx.compose.material3.tokens.A.g;
        c = androidx.compose.material3.tokens.A.f;
        float f3 = androidx.compose.material3.tokens.A.d;
        d = f3;
        e = (f3 - f2) / 2;
        f = new C0249j0();
        g = new androidx.compose.animation.core.K0(100, (androidx.compose.animation.core.B) null, 6);
    }

    public static final void a(boolean z, Function1 function1, androidx.compose.ui.q qVar, boolean z2, C0636i4 c0636i4, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVarB;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1580463220);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i & 24576) == 0) {
            i3 |= c0814p.g(z2) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.f(c0636i4) ? 131072 : 65536;
        }
        int i4 = i3 | 1572864;
        if ((599187 & i4) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            c0814p.X(783532531);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = androidx.compose.animation.d0.i(c0814p);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p.p(false);
            if (function1 != null) {
                androidx.compose.runtime.X0 x0 = F1.a;
                qVarB = androidx.compose.foundation.selection.d.b(MinimumInteractiveModifier.b, z, lVar, null, z2, new androidx.compose.ui.semantics.h(2), function1);
            } else {
                qVarB = androidx.compose.ui.n.b;
            }
            androidx.compose.ui.q qVarI = androidx.compose.foundation.layout.K0.i(androidx.compose.foundation.layout.K0.s(qVar.g(qVarB), androidx.compose.ui.b.e, 2), c, d);
            float f2 = androidx.compose.material3.tokens.A.a;
            int i5 = i4 << 3;
            int i6 = i4 >> 6;
            b(qVarI, z, z2, c0636i4, lVar, B3.a(c0814p, 5), c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | (i6 & 896) | (i6 & 7168) | (i5 & 57344));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0667j4(z, function1, qVar, z2, c0636i4, i);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, boolean z, boolean z2, C0636i4 c0636i4, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.graphics.V v, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long j;
        long j2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1594099146);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(c0636i4) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(null) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.f(lVar) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(v) ? 1048576 : 524288;
        }
        if ((i2 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            long j3 = z2 ? z ? c0636i4.b : c0636i4.f : z ? c0636i4.j : c0636i4.n;
            long j4 = z2 ? z ? c0636i4.a : c0636i4.e : z ? c0636i4.i : c0636i4.m;
            float f2 = androidx.compose.material3.tokens.A.a;
            androidx.compose.ui.graphics.V vA = B3.a(c0814p, 5);
            float f3 = androidx.compose.material3.tokens.A.e;
            if (!z2) {
                j = j3;
                j2 = z ? c0636i4.k : c0636i4.o;
            } else if (z) {
                j = j3;
                j2 = c0636i4.c;
            } else {
                j = j3;
                j2 = c0636i4.g;
            }
            androidx.compose.ui.q qVarF = AbstractC0460p.f(AbstractC0460p.g(qVar, f3, j2, vA), j, vA);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.q qVarF2 = AbstractC0460p.f(AbstractC0455m0.a(C0418x.a.a(androidx.compose.ui.n.b, androidx.compose.ui.b.d).g(new ThumbElement(lVar, z)), lVar, AbstractC0696o3.c(false, androidx.compose.material3.tokens.A.c / 2, 0L, c0814p, 54, 4)), j4, v);
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarF2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            c0814p.X(1163457794);
            c0814p.p(false);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0673k4(qVar, z, z2, c0636i4, lVar, v, i);
        }
    }
}
