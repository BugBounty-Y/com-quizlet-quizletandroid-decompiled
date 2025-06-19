package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.d6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3603d6 {
    public static final void a(com.quizlet.assembly.widgets.progress.c cVar, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.widgets.progress.b bVar;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1382584421);
        if (((i | (c0814p.f(cVar) ? 4 : 2) | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.w(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 1), "progressRow");
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarG);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true), "progressRowText");
            String strD = AbstractC3106b5.d(c0814p, cVar.a);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
            com.quizlet.assembly.widgets.progress.e eVar = cVar.c;
            int iOrdinal = eVar.ordinal();
            if (iOrdinal == 0) {
                i2 = R.attr.KnowColor;
            } else if (iOrdinal == 1) {
                i2 = R.attr.StillLearningColor;
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i2 = R.attr.LeftColor;
            }
            androidx.compose.material3.Q4.b(strD, qVarG2, androidx.compose.ui.graphics.F.c(com.quizlet.themes.extensions.a.a(context, i2)), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            int iOrdinal2 = eVar.ordinal();
            if (iOrdinal2 == 0) {
                bVar = com.quizlet.assembly.widgets.progress.b.d;
            } else if (iOrdinal2 == 1) {
                bVar = com.quizlet.assembly.widgets.progress.b.e;
            } else {
                if (iOrdinal2 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                bVar = com.quizlet.assembly.widgets.progress.b.f;
            }
            nVar2 = nVar3;
            AbstractC3587b6.a(String.valueOf(cVar.b), androidx.compose.ui.platform.N.G(AbstractC0460p.g(nVar2, com.quizlet.themes.m.h, ((C0861v) bVar.a.invoke(c0814p, 0)).a, com.quizlet.assembly.compose.pills.a.a), "progressRowPill"), ((C0861v) bVar.c.invoke(c0814p, 0)).a, ((C0861v) bVar.b.invoke(c0814p, 0)).a, 0L, null, null, c0814p, 0, ContentType.LONG_FORM_ON_DEMAND);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(cVar, nVar2, i, 5);
        }
    }

    public static final void b(com.quizlet.assembly.widgets.progress.d dVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.widgets.progress.d state = dVar;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1809802730);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(state) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC3737u5.a(state.a(), state.c(), androidx.compose.ui.platform.N.G(nVar, "arcProgressView"), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0L, 0L, c0814p, 384, 120);
            com.quizlet.themes.m.g.p();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, com.quizlet.ui.resources.designsystem.generated.j.j));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar);
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
            c0814p.X(-39459024);
            state = dVar;
            Iterator it2 = state.a.iterator();
            while (it2.hasNext()) {
                a((com.quizlet.assembly.widgets.progress.c) it2.next(), null, c0814p, 0);
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(state, qVar, i, 0);
        }
    }

    public abstract String c();
}
