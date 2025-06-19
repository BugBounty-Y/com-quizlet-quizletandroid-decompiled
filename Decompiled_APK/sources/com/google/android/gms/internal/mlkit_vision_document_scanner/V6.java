package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class V6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String motivationalMessage, androidx.compose.ui.q qVar, String str, androidx.compose.ui.graphics.painter.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar;
        Intrinsics.checkNotNullParameter(motivationalMessage, "motivationalMessage");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-310038465);
        int i2 = i | (c0814p.f(motivationalMessage) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.f(str) ? 256 : 128) | (c0814p.h(bVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
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
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(motivationalMessage, androidx.compose.ui.platform.N.G(nVar2, "motivational_message_title"), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, (i2 & 14) | 48, 0, 65528);
            c0814p = c0814p;
            c0814p.X(-1478673774);
            if (str == null || !(!StringsKt.O(str))) {
                nVar = nVar2;
            } else {
                androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).j;
                long jE = ((com.quizlet.themes.b) c0814p.j(b2)).b.e();
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar2, "motivational_message_description");
                com.quizlet.themes.m.g.s();
                nVar = nVar2;
                androidx.compose.material3.Q4.b(str, AbstractC0382e.y(qVarG, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p, (i2 >> 6) & 14, 0, 65528);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.p(true);
            c0814p.X(-1982402749);
            if (bVar != null) {
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                AbstractC0460p.c(bVar, null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.o(nVar, 88), "motivational_message_image"), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, ((i2 >> 9) & 14) | 48, 120);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(motivationalMessage, qVar, str, bVar, i);
        }
    }
}
