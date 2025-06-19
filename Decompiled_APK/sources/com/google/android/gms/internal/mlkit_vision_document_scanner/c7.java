package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class c7 {
    public static final void a(DefaultQuestionSectionData questionData, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.runtime.V v;
        androidx.compose.ui.n nVar;
        boolean z;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(questionData, "questionData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(327551075);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(questionData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v2 = C0804k.a;
            StudiableImage studiableImage = questionData.b;
            String strA = studiableImage != null ? studiableImage.a() : null;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar3);
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
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p, 48, 5);
            c0814p.X(99674941);
            if (strA == null) {
                nVar = nVar3;
                v = v2;
                z = false;
            } else {
                androidx.compose.ui.q qVarE = androidx.compose.foundation.layout.K0.e(androidx.compose.ui.platform.N.G(nVar3, "promptImage"), com.quizlet.themes.m.q, com.quizlet.themes.m.q0);
                c0814p.X(-1457909493);
                boolean zH = c0814p.h(xVarH);
                Object objI = c0814p.I();
                if (zH || objI == v2) {
                    objI = new com.quizlet.features.folders.changetags.composables.f(xVarH, 18);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                v = v2;
                nVar = nVar3;
                z = false;
                com.google.android.gms.internal.mlkit_vision_camera.r3.a(strA, null, AbstractC0460p.l(qVarE, false, null, (Function0) objI, 7), null, null, null, c0814p, 48, 2040);
            }
            c0814p.p(z);
            c0814p.X(99691830);
            StudiableText studiableText = questionData.a;
            if (studiableText == null) {
                nVar2 = nVar;
            } else {
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "text");
                c0814p.X(-1457901130);
                boolean zH2 = ((i3 & 896) == 256 ? true : z) | c0814p.h(questionData);
                Object objI2 = c0814p.I();
                if (zH2 || objI2 == v) {
                    objI2 = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(4, questionData, function1);
                    c0814p.i0(objI2);
                }
                c0814p.p(z);
                nVar2 = nVar;
                AbstractC3164i0.c(false, studiableText.a, studiableText.c, studiableText.b, AbstractC0460p.l(qVarG, z, null, (Function0) objI2, 7), ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l, 0L, 0, 0, null, null, c0814p, 6, 0, 1984);
                c0814p = c0814p;
                StudiableImage studiableImage2 = questionData.b;
                Z5.c(studiableImage2 != null ? studiableImage2.a() : null, null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
            }
            c0814p.p(z);
            c0814p.p(true);
            qVar2 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 21, questionData, qVar2, function1);
        }
    }

    public static final void b(DefaultQuestionSectionData firstQuestionData, DefaultQuestionSectionData defaultQuestionSectionData, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(firstQuestionData, "firstQuestionData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1585344554);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(firstQuestionData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(defaultQuestionSectionData) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            int i4 = i2 & 14;
            int i5 = i2 >> 3;
            a(firstQuestionData, null, function1, c0814p, i4 | (i5 & 896));
            c0814p.X(1473662921);
            if (defaultQuestionSectionData != null) {
                androidx.compose.material3.Z1.g(null, DefinitionKt.NO_Float_VALUE, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i(), c0814p, 0, 3);
                a(defaultQuestionSectionData, null, function1, c0814p, i5 & 910);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(firstQuestionData, defaultQuestionSectionData, qVar, function1, i, 4);
        }
    }

    public static final void c(com.quizlet.data.model.X x) {
        Intrinsics.checkNotNullParameter(x, "<this>");
        if (x.b == 0) {
            return;
        }
        if (x.c) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            C4933y.P(args);
        } else {
            Object[] args2 = {Integer.valueOf(x.a), Integer.valueOf(x.b)};
            Intrinsics.checkNotNullParameter(args2, "args");
            C4933y.P(args2);
        }
    }
}
