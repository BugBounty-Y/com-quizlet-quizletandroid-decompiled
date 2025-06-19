package androidx.compose.material3;

import androidx.compose.animation.core.C0230a;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.material3.tokens.AbstractC0727a;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class H {
    public static final float a = 4;
    public static final float b = 12;
    public static final float c = 14;
    public static final float d = 6;

    public static final void a(androidx.compose.ui.q qVar, long j, long j2, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.graphics.V vA;
        long j3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1298144073);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.e(j) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.e(j2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            j3 = j2;
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            float f = dVar != null ? AbstractC0727a.a : AbstractC0727a.b;
            if (dVar != null) {
                c0814p.X(-1271801170);
                vA = B3.a(c0814p, 5);
                c0814p.p(false);
            } else {
                c0814p.X(-1271743789);
                vA = B3.a(c0814p, 5);
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.foundation.layout.K0.a(qVar, f, f), j, vA);
            androidx.compose.ui.q qVarW = androidx.compose.ui.n.b;
            if (dVar != null) {
                qVarW = AbstractC0382e.w(qVarW, a, DefinitionKt.NO_Float_VALUE, 2);
            }
            androidx.compose.ui.q qVarG = qVarF.g(qVarW);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.e, androidx.compose.ui.b.k, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-1705294841);
            if (dVar != null) {
                j3 = j2;
                AbstractC0646j.a(j3, Z4.a(androidx.compose.material3.tokens.G.h, c0814p), androidx.compose.runtime.internal.e.e(719214594, new E(dVar, 0), c0814p), c0814p, ((i2 >> 6) & 14) | 384);
            } else {
                j3 = j2;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new F(qVar, j, j3, dVar, i);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.runtime.internal.d dVar2 = com.quizlet.assembly.compose.pills.k.a;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1404022535);
        if ((((c0814p.f(qVar) ? 32 : 16) | i) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.v(DefinitionKt.NO_Float_VALUE);
                c0814p.i0(objI);
            }
            androidx.compose.runtime.F0 f0 = (androidx.compose.runtime.F0) objI;
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = C0776c.v(DefinitionKt.NO_Float_VALUE);
                c0814p.i0(objI2);
            }
            androidx.compose.runtime.F0 f02 = (androidx.compose.runtime.F0) objI2;
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = C0776c.v(Float.POSITIVE_INFINITY);
                c0814p.i0(objI3);
            }
            androidx.compose.runtime.F0 f03 = (androidx.compose.runtime.F0) objI3;
            Object objI4 = c0814p.I();
            if (objI4 == v) {
                objI4 = C0776c.v(Float.NEGATIVE_INFINITY);
                c0814p.i0(objI4);
            }
            androidx.compose.runtime.F0 f04 = (androidx.compose.runtime.F0) objI4;
            Object objI5 = c0814p.I();
            if (objI5 == v) {
                C0230a c0230a = new C0230a(f0, f02, f03, f04, 4);
                c0814p.i0(c0230a);
                objI5 = c0230a;
            }
            androidx.compose.ui.q qVarL = AbstractC0897s.l(qVar, (Function1) objI5);
            Object objI6 = c0814p.I();
            if (objI6 == v) {
                objI6 = new com.quizlet.features.emailconfirmation.ui.composables.k(f02, f0, f03, f04);
                c0814p.i0(objI6);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI6;
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, k, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarK = AbstractC0897s.k(nVar, "anchor");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarK);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            Object obj = C0418x.a;
            dVar.invoke(obj, c0814p, 54);
            c0814p.p(true);
            androidx.compose.ui.q qVarK2 = AbstractC0897s.k(nVar, "badge");
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarK2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            dVar2.invoke(obj, c0814p, 54);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.text.selection.e0(qVar, dVar, i, 2);
        }
    }
}
