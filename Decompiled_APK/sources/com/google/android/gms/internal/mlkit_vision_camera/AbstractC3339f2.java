package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.pager.C0464c;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
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
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.compose.C1280m;
import androidx.transition.C1413p;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.WeakHashMap;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C5081j;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.f2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3339f2 {
    public static final void a(com.quizlet.features.practicetest.results.data.t tVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1331014618);
        int i2 = i | (c0814p.h(tVar) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = C0804k.a;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.s();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarC, com.quizlet.ui.resources.designsystem.generated.j.h, f);
            c0814p.X(-169662578);
            int i3 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i4 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, i4 | 32), new C0416v0(C0380d.e(c0814p).k, i4));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarV, c0374a);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarB);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_take_new_test_button);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.practice_test_retake_test_button);
            c0814p.X(282254828);
            boolean zH = c0814p.h(xVarH);
            Object objI = c0814p.I();
            if (zH || objI == obj) {
                objI = new com.quizlet.features.folders.changetags.composables.f(xVarH, 11);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(282257191);
            int i6 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z = i6 == 32;
            Object objI2 = c0814p.I();
            if (z || objI2 == obj) {
                objI2 = new com.quizlet.features.practicetest.detail.m(8, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            T1.a(strD, strD2, function0, (Function0) objI2, null, 0, null, !tVar.f, c0814p, 0, ContentType.LONG_FORM_ON_DEMAND);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "ConfigurationModal");
            PracticeTestConfigurationData practiceTestConfigurationData = tVar.e;
            kotlinx.collections.immutable.g gVarL = AbstractC3409x1.l(tVar.d);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.practice_test_take_new_test_button);
            c0814p.X(282282975);
            boolean zH2 = (i6 == 32) | c0814p.h(xVarH);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == obj) {
                objI3 = new com.quizlet.features.practicetest.results.b(function1, xVarH);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            N1.a(xVarH, practiceTestConfigurationData.a, gVarL, false, qVarG, true, false, null, null, strD3, false, (kotlin.jvm.functions.c) objI3, null, null, c0814p, 27656, 0, 13696);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.a(tVar, function1, i, 0);
        }
    }

    public static final void b(com.quizlet.features.practicetest.results.data.t tVar, androidx.compose.foundation.lazy.A a, Function2 function2, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1692993652);
        int i2 = i | (c0814p.h(tVar) ? 4 : 2) | (c0814p.f(a) ? 32 : 16) | (c0814p.h(function2) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.b, false);
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(androidx.compose.ui.n.b, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.U0, 1);
            c0814p.X(-432155183);
            boolean zH = ((i2 & 896) == 256) | c0814p.h(tVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.lifecycle.u0(27, tVar, function2);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarQ, a, null, null, null, null, false, (Function1) objI, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND, 252);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(tVar, a, function2, qVar, i, 20);
        }
    }

    public static final void c(com.quizlet.features.practicetest.results.data.u uVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-852548289);
        int i2 = (c0814p.f(uVar) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(nVar, "PracticeTestErrorScreen"), androidx.compose.runtime.internal.e.e(1817380917, new com.quizlet.features.achievements.ui.composables.E(2, function1), c0814p), null, null, null, 0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(-1521717558, new com.quizlet.baseui.base.d(uVar, 6), c0814p), c0814p, 805306422, 444);
            c0814p.X(-497018514);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.practicetest.detail.m(6, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.work.impl.t.a(false, (Function0) objI, c0814p, 0, 1);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(uVar, function1, i, 28);
        }
    }

    public static final void d(int i, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        String strH;
        int i3 = 1;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(472341786);
        int i4 = (c0814p.d(i) ? 4 : 2) | i2 | (c0814p.h(function1) ? 32 : 16);
        if ((i4 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1506047170);
            if (i > 0) {
                c0814p.X(-992157823);
                strH = AbstractC3106b5.b(R.plurals.paywall_get_quizlet_plus_free_trial_button, i, new Object[]{Integer.valueOf(i)}, c0814p);
                c0814p.p(false);
            } else {
                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -991988780, R.string.practice_test_paywall_container_button_text, c0814p, false);
            }
            String str = strH;
            c0814p.p(false);
            c0814p.X(-408821326);
            boolean z = (i4 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.practicetest.detail.m(5, function1);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-169662578);
            int i5 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i6 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, 32 | i6), new C0416v0(C0380d.e(c0814p).k, i6));
            c0814p.p(false);
            P1.a(0, 0, c0814p, androidx.compose.foundation.layout.U0.b(nVar, c0374a), str, function0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.d(i, i2, i3, function1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v0 */
    /* JADX WARN: Type inference failed for: r15v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r15v2 */
    public static final void e(kotlinx.coroutines.flow.W reportFlow, kotlin.jvm.functions.d navigateToTakeTest, Function2 navigateToDetails, Function2 navigateToReportContent, Function2 function2, com.quizlet.features.practicetest.results.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        Object obj;
        ?? r15;
        int i2;
        com.quizlet.features.practicetest.results.viewmodel.a aVar2;
        com.quizlet.features.practicetest.results.viewmodel.a aVar3;
        com.quizlet.features.practicetest.results.viewmodel.a aVar4;
        com.quizlet.features.practicetest.results.viewmodel.a aVar5;
        Intrinsics.checkNotNullParameter(reportFlow, "reportFlow");
        Intrinsics.checkNotNullParameter(navigateToTakeTest, "navigateToTakeTest");
        Intrinsics.checkNotNullParameter(navigateToDetails, "navigateToDetails");
        Intrinsics.checkNotNullParameter(navigateToReportContent, "navigateToReportContent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1347647980);
        int i3 = i | (c0814p.h(reportFlow) ? 4 : 2) | (c0814p.h(navigateToTakeTest) ? 32 : 16) | (c0814p.h(navigateToDetails) ? 256 : 128) | (c0814p.h(navigateToReportContent) ? 2048 : 1024) | (c0814p.h(function2) ? 16384 : 8192) | 65536;
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            aVar4 = aVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            Object obj2 = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                obj = obj2;
                r15 = 0;
                Object objE = AbstractC3417z1.e(com.quizlet.features.practicetest.results.viewmodel.h.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.practicetest.results.viewmodel.a aVar6 = (com.quizlet.features.practicetest.results.viewmodel.a) objE;
                i2 = i3 & (-458753);
                aVar2 = aVar6;
            } else {
                c0814p.Q();
                i2 = i3 & (-458753);
                obj = obj2;
                r15 = 0;
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.features.practicetest.results.viewmodel.h hVar = (com.quizlet.features.practicetest.results.viewmodel.h) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(hVar.m, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = hVar.l;
            c0814p.X(330675344);
            boolean z = ((i2 & 896) == 256 ? true : r15) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32 ? true : r15) | ((i2 & 7168) == 2048 ? true : r15) | ((i2 & 57344) != 16384 ? r15 : true);
            Object objI = c0814p.I();
            Object obj3 = obj;
            if (z || objI == obj3) {
                com.quizlet.features.practicetest.results.g gVar = new com.quizlet.features.practicetest.results.g(navigateToDetails, navigateToTakeTest, navigateToReportContent, function2, null);
                c0814p.i0(gVar);
                objI = gVar;
            }
            c0814p.p(r15);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == obj3) {
                objI2 = new com.quizlet.features.practicetest.results.d(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(r15);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(r15);
            c0814p.X(330703535);
            boolean zH = c0814p.h(aVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == obj3) {
                objI3 = new com.quizlet.features.practicetest.results.h(aVar2, null);
                c0814p.i0(objI3);
            }
            c0814p.p(r15);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zH2 = c0814p.h(j2) | c0814p.h(reportFlow) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == obj3) {
                objI4 = new com.quizlet.features.practicetest.results.f(interfaceC0773a0D2, j2, null, reportFlow);
                c0814p.i0(objI4);
            }
            c0814p.p(r15);
            com.quizlet.features.practicetest.results.data.w wVar = (com.quizlet.features.practicetest.results.data.w) AbstractC4178x.k(unit, (Function2) objI4, c0814p, r15, interfaceC0773a0G);
            if (wVar instanceof com.quizlet.features.practicetest.results.data.t) {
                c0814p.X(330708664);
                com.quizlet.features.practicetest.results.data.w wVar2 = (com.quizlet.features.practicetest.results.data.w) interfaceC0773a0G.getValue();
                Intrinsics.e(wVar2, "null cannot be cast to non-null type com.quizlet.features.practicetest.results.data.PracticeTestResultsUiState.Content");
                com.quizlet.features.practicetest.results.data.t tVar = (com.quizlet.features.practicetest.results.data.t) wVar2;
                c0814p.X(330711722);
                boolean zH3 = c0814p.h(aVar2);
                Object objI5 = c0814p.I();
                if (zH3 || objI5 == obj3) {
                    com.quizlet.features.practicetest.results.viewmodel.a aVar7 = aVar2;
                    objI5 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, aVar7, com.quizlet.features.practicetest.results.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/features/practicetest/results/data/PracticeTestResultsEvent;)V", 0, 18);
                    aVar5 = aVar7;
                    c0814p.i0(objI5);
                } else {
                    aVar5 = aVar2;
                }
                c0814p.p(r15);
                f(tVar, (Function1) ((kotlin.reflect.f) objI5), c0814p, r15);
                c0814p.p(r15);
                aVar3 = aVar5;
            } else {
                com.quizlet.features.practicetest.results.viewmodel.a aVar8 = aVar2;
                if (wVar instanceof com.quizlet.features.practicetest.results.data.u) {
                    c0814p.X(330714331);
                    com.quizlet.features.practicetest.results.data.w wVar3 = (com.quizlet.features.practicetest.results.data.w) interfaceC0773a0G.getValue();
                    Intrinsics.e(wVar3, "null cannot be cast to non-null type com.quizlet.features.practicetest.results.data.PracticeTestResultsUiState.Error");
                    com.quizlet.features.practicetest.results.data.u uVar = (com.quizlet.features.practicetest.results.data.u) wVar3;
                    c0814p.X(330717482);
                    boolean zH4 = c0814p.h(aVar8);
                    Object objI6 = c0814p.I();
                    if (zH4 || objI6 == obj3) {
                        aVar3 = aVar8;
                        objI6 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, aVar3, com.quizlet.features.practicetest.results.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/features/practicetest/results/data/PracticeTestResultsEvent;)V", 0, 19);
                        c0814p.i0(objI6);
                    } else {
                        aVar3 = aVar8;
                    }
                    c0814p.p(r15);
                    c(uVar, (Function1) ((kotlin.reflect.f) objI6), c0814p, r15);
                    c0814p.p(r15);
                } else {
                    aVar3 = aVar8;
                    if (!Intrinsics.b(wVar, com.quizlet.features.practicetest.results.data.v.a)) {
                        throw com.google.android.gms.measurement.internal.Z.j(330706871, c0814p, r15);
                    }
                    c0814p.X(330719947);
                    AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
                    c0814p.p(r15);
                }
            }
            aVar4 = aVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(reportFlow, navigateToTakeTest, navigateToDetails, navigateToReportContent, function2, aVar4, i, 6);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0194  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0196  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x01c6  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x01c8  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x01d1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(com.quizlet.features.practicetest.results.data.t r29, kotlin.jvm.functions.Function1 r30, androidx.compose.runtime.InterfaceC0806l r31, int r32) {
        /*
            Method dump skipped, instructions count: 501
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2.f(com.quizlet.features.practicetest.results.data.t, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static okhttp3.q g(SSLSession sSLSession) throws IOException {
        List listM;
        Intrinsics.checkNotNullParameter(sSLSession, "<this>");
        String cipherSuite = sSLSession.getCipherSuite();
        if (cipherSuite == null) {
            throw new IllegalStateException("cipherSuite == null");
        }
        if (cipherSuite.equals("TLS_NULL_WITH_NULL_NULL") ? true : cipherSuite.equals("SSL_NULL_WITH_NULL_NULL")) {
            throw new IOException("cipherSuite == ".concat(cipherSuite));
        }
        C5081j c5081jD = C5081j.b.d(cipherSuite);
        String protocol = sSLSession.getProtocol();
        if (protocol == null) {
            throw new IllegalStateException("tlsVersion == null");
        }
        if ("NONE".equals(protocol)) {
            throw new IOException("tlsVersion == NONE");
        }
        okhttp3.L lI = C1413p.i(protocol);
        try {
            Certificate[] peerCertificates = sSLSession.getPeerCertificates();
            listM = peerCertificates != null ? okhttp3.internal.b.m(Arrays.copyOf(peerCertificates, peerCertificates.length)) : kotlin.collections.K.a;
        } catch (SSLPeerUnverifiedException unused) {
            listM = kotlin.collections.K.a;
        }
        Certificate[] localCertificates = sSLSession.getLocalCertificates();
        return new okhttp3.q(lI, c5081jD, localCertificates != null ? okhttp3.internal.b.m(Arrays.copyOf(localCertificates, localCertificates.length)) : kotlin.collections.K.a, new C0464c(listM, 2));
    }

    public static final void h(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        throw new IllegalArgumentException(android.support.v4.media.session.a.B("No valid saved state was found for the key '", key, "'. It may be missing, null, or not of the expected type. This can occur if the value was saved with a different type or if the saved state was modified unexpectedly."));
    }
}
