package androidx.compose.material3.pulltorefresh;

import androidx.compose.animation.E;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.AbstractC0590b0;
import androidx.compose.material3.Z;
import androidx.compose.material3.tokens.AbstractC0733g;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.X0;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();
    public static final androidx.compose.foundation.shape.d b = androidx.compose.foundation.shape.e.a;
    public static final float c = 80;
    public static final float d = AbstractC0733g.c;

    public final void a(q qVar, boolean z, androidx.compose.ui.q qVar2, long j, long j2, float f, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        float f2;
        long j3;
        long j4;
        float f3;
        long j5;
        long j6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1076870256);
        int i3 = i | (c0814p.f(qVar) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.f(qVar2) ? 256 : 128) | 74752;
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
            j5 = j;
            j6 = j2;
            f3 = f;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                X0 x0 = AbstractC0590b0.a;
                long j7 = ((Z) c0814p.j(x0)).G;
                long j8 = ((Z) c0814p.j(x0)).s;
                i2 = i3 & (-523265);
                f2 = c;
                j3 = j8;
                j4 = j7;
            } else {
                c0814p.Q();
                i2 = i3 & (-523265);
                j4 = j;
                j3 = j2;
                f2 = f;
            }
            c0814p.q();
            float f4 = g.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.draw.g.g(K0.k(qVar2, g.d), d.b);
            float f5 = d;
            androidx.compose.foundation.shape.d dVar = b;
            float f6 = f2;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(F.p(qVarG, new e(qVar, z, f6, f5, dVar)), j4, dVar);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i4 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            E.j(Boolean.valueOf(z), null, AbstractC0240f.r(100, 0, null, 6), null, androidx.compose.runtime.internal.e.e(167807595, new a(j3, qVar), c0814p), c0814p, ((i2 >> 3) & 14) | 24960);
            c0814p.p(true);
            f3 = f6;
            j5 = j4;
            j6 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new b(this, qVar, z, qVar2, j5, j6, f3, i);
        }
    }
}
