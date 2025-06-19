package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z5 {
    public static final void a(kotlinx.collections.immutable.b getStartedCardData, com.quizlet.quizletandroid.ui.globalnav.composable.s onGetStartedImpression, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(getStartedCardData, "getStartedCardData");
        Intrinsics.checkNotNullParameter(onGetStartedImpression, "onGetStartedImpression");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(536986900);
        int i2 = i | (c0814p.h(getStartedCardData) ? 4 : 2) | (c0814p.h(onGetStartedImpression) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar3, f, DefinitionKt.NO_Float_VALUE, f, f, 2), 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.home_new_empty_subtitle);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).i;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            mVar.p();
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.X(694401746);
            Iterator<E> it2 = getStartedCardData.iterator();
            while (it2.hasNext()) {
                com.quizlet.quizletandroid.ui.startpage.nav2.composables.e eVar = (com.quizlet.quizletandroid.ui.startpage.nav2.composables.e) it2.next();
                b(eVar.a, null, eVar.b, c0814p, 0);
            }
            c0814p.p(false);
            c0814p.p(true);
            Object[] objArr = new Object[0];
            c0814p.X(-817670849);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            c0814p.X(-817669409);
            boolean zF = c0814p.f(interfaceC0773a0) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p.h(getStartedCardData);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new androidx.work.impl.utils.q(onGetStartedImpression, getStartedCardData, interfaceC0773a0, 29);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.i((Function0) objI2, c0814p);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 28, getStartedCardData, onGetStartedImpression, nVar2);
        }
    }

    public static final void b(com.quizlet.ui.models.content.home.f fVar, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-798881949);
        int i2 = i | (c0814p2.h(fVar) ? 4 : 2) | 48 | (c0814p2.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            nVar2 = nVar3;
            c0814p = c0814p2;
            R4.a(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, 0L, 0L, 0L, function0, false, null, null, null, androidx.compose.runtime.internal.e.e(-433598563, new com.quizlet.assembly.compose.cards.c(fVar, 28), c0814p2), c0814p, (i2 << 9) & 458752, 990);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 29, (androidx.compose.ui.q) nVar2, (Object) fVar, (Object) function0);
        }
    }

    public static final void c(String str, androidx.compose.ui.n nVar, com.quizlet.assembly.compose.modals.x xVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1905800481);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(xVar) ? 256 : 128;
        }
        int i4 = i3;
        if ((i4 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                nVar = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
            }
            c0814p2.q();
            c0814p2.X(1998459392);
            boolean zH = c0814p2.h(xVar);
            Object objI = c0814p2.I();
            if (zH || objI == C0804k.a) {
                androidx.activity.K k = new androidx.activity.K(0, xVar, com.quizlet.assembly.compose.modals.x.class, "hide", "hide()V", 0, 15);
                c0814p2.i0(k);
                objI = k;
            }
            c0814p2.p(false);
            androidx.compose.ui.window.r rVar = new androidx.compose.ui.window.r(3);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-571347251, new androidx.navigation.compose.o(8, str, xVar), c0814p2);
            int i5 = i4 >> 3;
            int i6 = (i5 & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 14) | 1772544;
            c0814p = c0814p2;
            androidx.compose.ui.n nVar3 = nVar;
            V5.a(nVar3, xVar, false, com.quizlet.assembly.compose.modals.B.a, (Function0) ((kotlin.reflect.f) objI), rVar, dVarE, c0814p, i6, 4);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 4, str, nVar2, xVar);
        }
    }
}
