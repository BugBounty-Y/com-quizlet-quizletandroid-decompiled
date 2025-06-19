package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.material3.AbstractC0666j3;
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
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class j7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function1 function1, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1604369620);
        int i2 = (c0814p.f(qVar) ? 4 : 2) | i | (c0814p.g(z) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            androidx.compose.ui.q qVarG = qVar.g(fillElement);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(910605524);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = com.quizlet.explanations.questiondetail.ui.composables.d.a;
                c0814p.i0(objI);
            }
            c0814p.p(false);
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) ((kotlin.reflect.f) objI);
            c0814p.X(910607459);
            boolean z2 = (i2 & 896) == 256;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new androidx.navigation.compose.B(1, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            androidx.compose.ui.viewinterop.k.d(cVar, fillElement, (Function1) objI2, c0814p, 54);
            c0814p.X(910610025);
            if (z) {
                AbstractC0666j3.a(androidx.compose.ui.platform.N.G(c0418x.a(nVar, androidx.compose.ui.b.e), "ExplanationQuestionContentLoading"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).K(), DefinitionKt.NO_Float_VALUE, 0L, 0, c0814p, 0, 28);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.c(qVar, z, function1, i);
        }
    }
}
