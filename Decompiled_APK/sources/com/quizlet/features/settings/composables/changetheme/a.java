package com.quizlet.features.settings.composables.changetheme;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.D1;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3524r3;
import com.quizlet.assembly.compose.menu.i;
import com.quizlet.explanations.questiondetail.ui.composables.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.f;
import com.quizlet.themes.g;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.h;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final List a = B.j(com.quizlet.themes.nighttheme.a.d, com.quizlet.themes.nighttheme.a.e, com.quizlet.themes.nighttheme.a.c);

    public static final void a(com.quizlet.themes.nighttheme.a selectedTheme, q qVar, A0 a0, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        A0 a02;
        int i3;
        A0 a03;
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(selectedTheme, "selectedTheme");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-130019201);
        int i4 = i | (c0814p.f(selectedTheme) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            a02 = a0;
        } else {
            a02 = a0;
            i3 = i4 | (c0814p.f(a02) ? 256 : 128);
        }
        int i6 = i3 | (c0814p.h(function1) ? 2048 : 1024);
        if ((i6 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            a03 = a02;
        } else {
            float f = DefinitionKt.NO_Float_VALUE;
            A0 a0C = i5 != 0 ? AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 3) : a02;
            V v = C0804k.a;
            C0380d c0380d = AbstractC0398m.a;
            m.g.u();
            androidx.compose.foundation.layout.B bA = A.a(AbstractC0398m.g(j.g), androidx.compose.ui.b.m, c0814p, 0);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(258164340);
            for (com.quizlet.themes.nighttheme.a aVar : a) {
                n nVar = n.b;
                m.g.u();
                q qVarT = AbstractC0382e.t(AbstractC0382e.w(nVar, f, j.g, 1), a0C);
                if (selectedTheme == aVar) {
                    z2 = true;
                    z = true;
                } else {
                    z = true;
                    z2 = false;
                }
                String strA = AbstractC3524r3.a(aVar, c0814p);
                c0814p.X(-1822385976);
                if ((i6 & 7168) != 2048) {
                    z = false;
                }
                boolean zF = z | c0814p.f(aVar);
                Object objI = c0814p.I();
                if (zF || objI == v) {
                    objI = new com.quizlet.features.questionnaire.screens.c(9, function1, aVar);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                b(z2, strA, qVarT, (Function0) objI, c0814p, 0);
                f = DefinitionKt.NO_Float_VALUE;
            }
            c0814p.p(false);
            c0814p.p(true);
            a03 = a0C;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new i(selectedTheme, qVar, a03, function1, i, i2);
        }
    }

    public static final void b(boolean z, String str, q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        long jF;
        String str2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1874586247);
        int i2 = i | (c0814p.g(z) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
        } else {
            q qVarL = AbstractC0460p.l(qVar, false, null, function0, 7);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarL);
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
            n nVar = n.b;
            q qVarC2 = K0.c(nVar, 1.0f);
            m mVar = m.g;
            mVar.h();
            float f = h.g;
            q qVarF = K0.f(qVarC2, f, DefinitionKt.NO_Float_VALUE, 2);
            G0 g0B = E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarF);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            L l = ((f) c0814p.j(w.a)).j;
            if (z) {
                c0814p.X(-1387720111);
                jF = ((com.quizlet.themes.b) c0814p.j(g.a)).e;
                c0814p.p(false);
            } else {
                c0814p.X(-1387646269);
                jF = ((com.quizlet.themes.b) c0814p.j(g.a)).b.f();
                c0814p.p(false);
            }
            Q4.b(str, null, jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, (i2 >> 3) & 14, 0, 65530);
            str2 = str;
            c0814p = c0814p;
            c0814p.X(2033451041);
            if (z) {
                mVar.h();
                q qVarG = N.G(K0.k(nVar, f), str2 + "_isSelected");
                com.quizlet.themes.e.a(c0814p).a.getClass();
                D1.a(com.quizlet.ui.resources.icons.d.p(c0814p), AbstractC3106b5.d(c0814p, R.string.checked_a11y), qVarG, ((com.quizlet.themes.b) c0814p.j(g.a)).e, c0814p, 0, 0);
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new o(z, str2, qVar, function0, i, 3);
        }
    }
}
