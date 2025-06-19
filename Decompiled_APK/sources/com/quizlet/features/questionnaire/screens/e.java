package com.quizlet.features.questionnaire.screens;

import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.K0;
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
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.questionnaire.navigation.StepModel;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class e {
    public static final void a(com.quizlet.features.questionnaire.steps.b bVar, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.questionnaire.steps.b bVar2;
        com.quizlet.features.questionnaire.steps.b viewModel = bVar;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1158349455);
        int i2 = i | (c0814p.f(viewModel) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16);
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
            C0418x c0418x = C0418x.a;
            StepModel.Intro intro = viewModel.b;
            n nVar = n.b;
            FillElement fillElement = K0.c;
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
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
            String str = intro.e;
            androidx.compose.runtime.B b = w.a;
            L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65018);
            L l2 = ((com.quizlet.themes.f) c0814p.j(b)).j;
            long jF = ((com.quizlet.themes.b) c0814p.j(b2)).b.f();
            m mVar = m.g;
            mVar.s();
            Q4.b(intro.f, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l2, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(intro.c);
            mVar.p();
            q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(458255802);
            int i5 = i2 & 14;
            boolean z = i5 == 4;
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (z || objI == v) {
                bVar2 = bVar;
                objI = new J(bVar2, 9);
                c0814p.i0(objI);
            } else {
                bVar2 = bVar;
            }
            c0814p.p(false);
            com.quizlet.features.questionnaire.options.b.b(bVarI, qVarY, (Function1) objI, c0814p, 0);
            c0814p.p(true);
            mVar.o();
            q qVarA = c0418x.a(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.p, 7), androidx.compose.ui.b.h);
            String str2 = intro.d.a;
            C4076a c4076a = C4076a.m;
            c0814p.X(854054276);
            boolean zH = c0814p.h(intro) | (i5 == 4);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new c(0, bVar2, intro);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            viewModel = bVar;
            AbstractC3586b5.a(str2, qVarA, (Function0) objI2, false, c4076a, null, null, null, null, c0814p, 0, 1000);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new d(viewModel, qVar, i, 0);
        }
    }
}
