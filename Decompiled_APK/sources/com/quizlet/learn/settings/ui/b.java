package com.quizlet.learn.settings.ui;

import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.AbstractC0684m3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.g;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.h;
import androidx.compose.ui.semantics.m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.themes.f;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.j;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.collections.immutable.c;
import kotlinx.collections.immutable.e;

/* loaded from: classes3.dex */
public abstract class b {
    public static final e a = AbstractC3409x1.h(WrittenQuestionGradingOption.Relaxed.e, WrittenQuestionGradingOption.Moderate.e, WrittenQuestionGradingOption.Strict.e);

    public static final void a(c cVar, WrittenQuestionGradingOption selectedOption, Function1 function1, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long jB;
        boolean z;
        long jB2;
        Set enabledGradingOptionList = cVar;
        Function1 onOptionSelected = function1;
        Intrinsics.checkNotNullParameter(enabledGradingOptionList, "enabledGradingOptionList");
        Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
        Intrinsics.checkNotNullParameter(onOptionSelected, "onOptionSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1945497538);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(enabledGradingOptionList) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(selectedOption) ? 32 : 16;
        }
        int i3 = 256;
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onOptionSelected) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z2 = false;
            q qVarA = m.a(qVar, false, androidx.compose.foundation.selection.a.a);
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.q();
            C0392j c0392jG = AbstractC0398m.g(j.i);
            g gVar = androidx.compose.ui.b.m;
            B bA = A.a(c0392jG, gVar, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarA);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1011417896);
            Iterator it2 = a.iterator();
            while (it2.hasNext()) {
                WrittenQuestionGradingOption writtenQuestionGradingOption = (WrittenQuestionGradingOption) it2.next();
                boolean zContains = enabledGradingOptionList.contains(writtenQuestionGradingOption);
                n nVar = n.b;
                boolean zB = Intrinsics.b(writtenQuestionGradingOption, selectedOption);
                h hVar = new h(3);
                c0814p.X(386580487);
                boolean zF = ((i2 & 896) == i3) | c0814p.f(writtenQuestionGradingOption);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new com.quizlet.features.questionnaire.screens.c(18, onOptionSelected, writtenQuestionGradingOption);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                q qVarA2 = androidx.compose.ui.a.a(nVar, new androidx.compose.foundation.selection.b(zB, zContains, hVar, (Function0) objI));
                C0380d c0380d2 = AbstractC0398m.a;
                com.quizlet.themes.m.g.u();
                B bA2 = A.a(AbstractC0398m.g(j.g), gVar, c0814p, 0);
                int i5 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarA2);
                InterfaceC0915k.D0.getClass();
                Iterator it3 = it2;
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0912h c0912h2 = C0914j.f;
                C0776c.E(c0814p, bA2, c0912h2);
                C0912h c0912h3 = C0914j.e;
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h3);
                C0912h c0912h4 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                    android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h4);
                }
                C0912h c0912h5 = C0914j.d;
                C0776c.E(c0814p, qVarC2, c0912h5);
                q qVarC3 = K0.c(nVar, 1.0f);
                G0 g0B = E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
                int i6 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarC3);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, c0912h2);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h3);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                    android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h4);
                }
                C0776c.E(c0814p, qVarC4, c0912h5);
                String strD = AbstractC3106b5.d(c0814p, writtenQuestionGradingOption.a);
                if (zContains) {
                    c0814p.X(-808273865);
                    jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                    c0814p.p(false);
                    z = false;
                } else {
                    c0814p.X(-808170852);
                    jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.b();
                    z = false;
                    c0814p.p(false);
                }
                androidx.compose.runtime.B b = w.a;
                g gVar2 = gVar;
                C0814p c0814p2 = c0814p;
                long j = jB;
                boolean z3 = z;
                Q4.b(strD, null, j, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((f) c0814p.j(b)).j, c0814p2, 0, 0, 65530);
                if (1.0f <= 0.0d) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
                }
                AbstractC0382e.f(c0814p2, new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true));
                AbstractC0684m3.a(writtenQuestionGradingOption.equals(selectedOption), null, null, zContains, null, c0814p2, 48, 52);
                c0814p2.p(true);
                String strD2 = AbstractC3106b5.d(c0814p2, writtenQuestionGradingOption.b);
                if (zContains) {
                    c0814p2.X(-312131906);
                    jB2 = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
                    c0814p2.p(z3);
                } else {
                    c0814p2.X(-312036829);
                    jB2 = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.b();
                    c0814p2.p(z3);
                }
                Q4.b(strD2, null, jB2, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((f) c0814p2.j(b)).p, c0814p2, 0, 0, 65530);
                c0814p = c0814p2;
                c0814p.p(true);
                enabledGradingOptionList = cVar;
                z2 = z3;
                gVar = gVar2;
                it2 = it3;
                i3 = 256;
                onOptionSelected = function1;
            }
            c0814p.p(z2);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new a(cVar, selectedOption, function1, qVar, i, 0);
        }
    }
}
