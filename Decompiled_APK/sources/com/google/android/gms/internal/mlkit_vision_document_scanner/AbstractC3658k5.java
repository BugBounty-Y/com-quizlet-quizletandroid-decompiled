package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.VerticalAlignElement;
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
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.k5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3658k5 {
    public static final void a(String str, String str2, String str3, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.runtime.B b;
        androidx.compose.runtime.B b2;
        boolean z;
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-285992967);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.f(str3) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            androidx.compose.runtime.B b3 = com.quizlet.themes.w.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b3)).l;
            androidx.compose.runtime.B b4 = com.quizlet.themes.g.a;
            androidx.compose.ui.n nVar2 = nVar;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b4)).b.f(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, l, c0814p, i2 & 14, 3120, 55290);
            c0814p = c0814p;
            c0814p.X(-507525709);
            if (str2 == null) {
                b = b3;
                b2 = b4;
            } else {
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.u();
                float f = com.quizlet.ui.resources.designsystem.generated.j.g;
                c(AbstractC0382e.y(nVar2, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p, 6);
                mVar.u();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar2, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
                nVar2 = nVar2;
                b = b3;
                b2 = b4;
                androidx.compose.material3.Q4.b(str2, qVarY, ((com.quizlet.themes.b) c0814p.j(b4)).b.f(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, ((com.quizlet.themes.f) c0814p.j(b3)).l, c0814p, (i2 >> 3) & 14, 3120, 55288);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.X(-507509998);
            if (str3 == null) {
                z = false;
            } else {
                com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
                mVar2.u();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
                androidx.compose.ui.n nVar3 = nVar2;
                c(AbstractC0382e.y(nVar3, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p, 6);
                mVar2.u();
                nVar2 = nVar3;
                C0814p c0814p2 = c0814p;
                androidx.compose.material3.Q4.b(str3, AbstractC0382e.y(nVar3, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).l, c0814p2, (i2 >> 6) & 14, 3120, 55288);
                c0814p = c0814p2;
                z = false;
            }
            c0814p.p(z);
            c0814p.p(true);
            qVar2 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(str, str2, str3, qVar2, i, 1);
        }
    }

    public static final void b(com.quizlet.ui.models.content.carditem.b exerciseCardModel, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(exerciseCardModel, "exerciseCardModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-27086814);
        int i4 = i | (c0814p2.h(exerciseCardModel) ? 4 : 2);
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 32 : 16);
        }
        int i6 = i3 | 384 | (c0814p2.h(function1) ? 2048 : 1024);
        if ((i6 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar3 = qVar2;
        } else {
            androidx.compose.ui.q qVar4 = i5 != 0 ? androidx.compose.ui.n.b : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.d(qVar4, 156), 1.0f), "ExerciseCard");
            c0814p2.X(-2089971504);
            boolean zH = ((i6 & 7168) == 2048) | c0814p2.h(exerciseCardModel);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.braze.triggers.managers.h(14, function1, exerciseCardModel);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            R4.a(qVarG, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-1595199960, new com.quizlet.assembly.compose.cards.c(exerciseCardModel, 1), c0814p2), c0814p, 0, 990);
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, i2, 1, exerciseCardModel, qVar3, function1);
        }
    }

    public static final void c(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1867426435);
        if ((((c0814p.f(qVar) ? 32 : 16) | i) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.n();
            androidx.compose.ui.q qVarL = androidx.compose.foundation.layout.K0.l(qVar, 1, com.quizlet.ui.resources.designsystem.generated.j.o);
            long jI = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i();
            mVar.c();
            AbstractC0409s.a(AbstractC0460p.f(qVarL, jI, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h)).g(new VerticalAlignElement(androidx.compose.ui.b.k)), c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 0, qVar);
        }
    }

    public static final void d(String title, String subTitle, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(subTitle, "subTitle");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1396536326);
        int i2 = i | (c0814p2.f(title) ? 4 : 2) | (c0814p2.f(subTitle) ? 32 : 16) | 384 | (c0814p2.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            R4.a(androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), null, 0L, 0L, 0L, function0, false, null, null, null, androidx.compose.runtime.internal.e.e(1043581504, new com.quizlet.assembly.compose.input.l(3, title, subTitle), c0814p2), c0814p, (i2 << 6) & 458752, 990);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(title, subTitle, nVar2, function0, i, 2);
        }
    }
}
