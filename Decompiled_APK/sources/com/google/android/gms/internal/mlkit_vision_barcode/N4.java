package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.C0923t;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N4 {
    public static final void a(String str, String str2, com.quizlet.security.challenge.viewmodel.a aVar, Function0 function0, Function0 function02, androidx.compose.ui.q qVar, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1574764329);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.f(aVar) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536) | (c0814p.g(z) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.security_challenge_message), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).o, c0814p, 0, 0, 65532);
            c(str, str2, aVar, function0, androidx.compose.foundation.layout.C.a(nVar, 1.0f), c0814p, i2 & 8190);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.s();
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(AbstractC3106b5.d(c0814p, R.string.security_challenge_continue), AbstractC0382e.w(qVarC2, DefinitionKt.NO_Float_VALUE, f, 1), function02, z, null, null, null, null, null, false, c0814p, ((i2 >> 6) & 896) | ((i2 >> 9) & 7168), 1008);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(str, str2, aVar, function0, function02, qVar, z, i);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-164550711);
        if ((((c0814p.h(function0) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3691o6.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, AbstractC3106b5.d(c0814p, R.string.security_challenge_title), androidx.compose.runtime.internal.e.e(-741117324, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(7, function0), c0814p), null, null, c0814p, 196608, 205);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 12, function0);
        }
    }

    public static final void c(String str, String str2, com.quizlet.security.challenge.viewmodel.a aVar, Function0 function0, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.runtime.V v;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-508212647);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(str2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(aVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            Map mapB = kotlin.collections.U.b(new Pair("Accept-Language", Locale.getDefault().toLanguageTag()));
            Object[] objArr = new Object[0];
            c0814p.X(1757057028);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (objI == v2) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(15);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            c0814p.X(1757058792);
            Object objI2 = c0814p.I();
            if (objI2 == v2) {
                objI2 = new com.quizlet.security.challenge.ui.a(interfaceC0773a0);
                c0814p.i0(objI2);
            }
            com.quizlet.security.challenge.ui.a aVar2 = (com.quizlet.security.challenge.ui.a) objI2;
            c0814p.p(false);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-1309107142);
            boolean zF = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256) | ((i2 & 14) == 4) | c0814p.f(mapB);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v2) {
                v = v2;
                androidx.navigation.internal.i iVar = new androidx.navigation.internal.i(aVar2, str2, aVar, str, mapB, 4);
                c0814p.i0(iVar);
                objI3 = iVar;
            } else {
                v = v2;
            }
            Function1 function1 = (Function1) objI3;
            c0814p.p(false);
            c0814p.X(-1309083972);
            boolean z = (i2 & 7168) == 2048;
            Object objI4 = c0814p.I();
            if (z || objI4 == v) {
                objI4 = new com.quizlet.assembly.compose.input.d(14, function0);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            androidx.compose.ui.viewinterop.k.b(function1, nVar, null, (Function1) objI4, null, c0814p, 48, 20);
            c0814p = c0814p;
            c0814p.X(-1309081704);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(str, str2, aVar, function0, qVar, i, 22);
        }
    }

    public static final void d(androidx.compose.ui.q qVar, com.quizlet.features.folders.data.K0 k0, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(977489048);
        int i2 = i | (c0814p.f(qVar) ? 4 : 2) | (c0814p.f(k0) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p);
            c0814p.X(667398067);
            List listJ = kotlin.collections.B.j(new com.quizlet.assembly.compose.menu.n(AbstractC3106b5.d(c0814p, R.string.sort)), g(R.string.sort_by_recent, k0.c(), c0814p), g(R.string.sort_by_title, k0.d(), c0814p));
            c0814p.p(false);
            sVarB.c(listJ, true);
            com.google.android.gms.internal.mlkit_vision_document_scanner.M5.a(androidx.compose.runtime.internal.e.e(-109692033, new com.quizlet.assembly.compose.menu.l(k0, function1, sVarB, 8), c0814p), qVar, sVarB, function12, null, null, c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 6 | (i2 & 7168), 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(qVar, k0, function1, function12, i, 7);
        }
    }

    public static final void e(com.quizlet.security.challenge.viewmodel.d viewModel, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-912750108);
        if ((((c0814p.h(viewModel) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            AbstractC0725t3.a(nVar2, androidx.compose.runtime.internal.e.e(1527206304, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(viewModel, 6), c0814p), null, null, null, 0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(940762933, new com.quizlet.features.questiontypes.mcq.ui.c(18, viewModel, C0776c.m(viewModel.i, c0814p)), c0814p), c0814p, 805306422, 444);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(viewModel, nVar2, i, 10);
        }
    }

    public static final boolean f(androidx.compose.ui.draganddrop.e eVar, long j) {
        if (!eVar.a.m) {
            return false;
        }
        C0923t c0923t = (C0923t) AbstractC0910f.v(eVar).w.c;
        if (!c0923t.K.m) {
            return false;
        }
        long j2 = c0923t.c;
        long jU = c0923t.U(0L);
        float fD = androidx.compose.ui.geometry.b.d(jU);
        float fE = androidx.compose.ui.geometry.b.e(jU);
        float f = ((int) (j2 >> 32)) + fD;
        float f2 = ((int) (j2 & 4294967295L)) + fE;
        float fD2 = androidx.compose.ui.geometry.b.d(j);
        if (fD > fD2 || fD2 > f) {
            return false;
        }
        float fE2 = androidx.compose.ui.geometry.b.e(j);
        return fE <= fE2 && fE2 <= f2;
    }

    public static final com.quizlet.assembly.compose.menu.o g(int i, com.quizlet.features.folders.data.H0 h0, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(310927024);
        com.quizlet.features.folders.data.K0 k0 = h0.a;
        String strD = AbstractC3106b5.d(c0814p, i);
        c0814p.X(936723058);
        Integer num = h0.b;
        androidx.compose.ui.graphics.painter.b bVarA = num == null ? null : Z4.a(num.intValue(), c0814p, 0);
        c0814p.p(false);
        c0814p.X(2005777542);
        com.quizlet.assembly.compose.menu.p pVar = h0.c ? com.quizlet.assembly.compose.menu.p.a : com.quizlet.assembly.compose.menu.p.d;
        c0814p.p(false);
        com.quizlet.assembly.compose.menu.o oVar = new com.quizlet.assembly.compose.menu.o(k0, strD, null, bVarA, false, pVar, false, SubsamplingScaleImageView.ORIENTATION_180);
        c0814p.p(false);
        return oVar;
    }
}
