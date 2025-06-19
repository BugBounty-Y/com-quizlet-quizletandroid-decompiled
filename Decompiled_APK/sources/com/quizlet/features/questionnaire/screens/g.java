package com.quizlet.features.questionnaire.screens;

import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.quizlet.features.questionnaire.navigation.Control;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class g {
    public static final void a(com.quizlet.features.questionnaire.steps.c viewModel, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(310554846);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(viewModel) : c0814p.h(viewModel) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
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
            FillElement fillElement = K0.c;
            B bA = A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, fillElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            int i5 = i2;
            Q4.b("School & Course Screen", null, C0861v.b, S5.g(24), null, 0L, null, 0L, 0, false, 0, 0, null, null, c0814p, 3462, 0, 131058);
            c0814p = c0814p;
            Control.Button button = viewModel.b.c;
            c0814p.X(-1095200494);
            boolean zF = ((i5 & 14) == 4 || ((i5 & 8) != 0 && c0814p.h(viewModel))) | c0814p.f(button);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                objI = new c(1, viewModel, button);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Z1.b((Function0) objI, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, 24, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), false, null, null, null, null, null, null, androidx.compose.runtime.internal.e.e(-1712726670, new f(button), c0814p), c0814p, 805306416, 508);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(viewModel, qVar, i, 18);
        }
    }
}
