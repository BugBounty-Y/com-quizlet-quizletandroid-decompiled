package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.D5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.universaluploadflow.data.C4463l;
import com.quizlet.features.universaluploadflow.data.n;
import com.quizlet.features.universaluploadflow.viewmodel.g;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N3 {
    /* JADX WARN: Removed duplicated region for block: B:118:0x0472  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0474  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0488  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x04a7  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x04b2  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x04bb  */
    /* JADX WARN: Type inference failed for: r13v17 */
    /* JADX WARN: Type inference failed for: r13v18, types: [java.lang.String, kotlin.jvm.internal.DefaultConstructorMarker] */
    /* JADX WARN: Type inference failed for: r13v20 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.universaluploadflow.data.G r50, kotlin.jvm.functions.Function1 r51, androidx.compose.ui.q r52, int r53, androidx.compose.runtime.InterfaceC0806l r54, int r55) {
        /*
            Method dump skipped, instructions count: 1452
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.N3.a(com.quizlet.features.universaluploadflow.data.G, kotlin.jvm.functions.Function1, androidx.compose.ui.q, int, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.universaluploadflow.data.K k, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function12;
        com.quizlet.features.universaluploadflow.data.K k2 = k;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-838247086);
        int i2 = (c0814p.f(k2) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function12 = function1;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(-1263052354);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            Object[] objArr = new Object[0];
            c0814p.X(-1263049580);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.c(10);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI2, c0814p, 3072, 6);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            com.quizlet.assembly.compose.modals.x xVarH2 = Y5.h(false, false, c0814p, 0, 7);
            c0814p.X(-1263043517);
            boolean z = ((i2 & 14) == 4) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI3 = c0814p.I();
            if (z || objI3 == v) {
                objI3 = new androidx.work.impl.utils.q(k2, function1, interfaceC0773a0, 23);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "UniversalUploadFlowActivity");
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-1410232042, new com.quizlet.assembly.compose.buttons.A(k2, (Function0) objI3, xVarH, xVarH2, 16), c0814p);
            k2 = k;
            function12 = function1;
            AbstractC0725t3.a(qVarG, dVarE, null, null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1186993887, new com.quizlet.features.blocks.ui.d(k2, function12, xVarH, interfaceC0773a02, xVarH2, interfaceC0773a0, 4), c0814p), c0814p, 805306422, 252);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(k2, function12, i, 11);
        }
    }

    public static final void c(Function0 function0, boolean z, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(53890628);
        int i2 = i | (c0814p.h(function0) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | (c0814p.h(function03) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(null, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function0, androidx.compose.runtime.internal.e.e(1280844834, new com.quizlet.assembly.compose.modals.k(z, function03, function02, 2), c0814p), null, c0814p, ((i2 << 15) & 458752) | 1572864, 139);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(function0, z, function02, function03, i, 4);
        }
    }

    public static final void d(com.quizlet.data.model.m2 source, Function0 navigateBack, Function1 navigateToWebPage, Function1 navigateToPasteText, Function1 navigateToFlashcards, Function1 navigateToPracticeTests, Function0 navigateToPaywall, Function0 navigateToLogin, Function0 navigateToSignUp, com.quizlet.features.universaluploadflow.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.universaluploadflow.viewmodel.a aVar2;
        int i2;
        int i3;
        com.quizlet.assembly.compose.modals.x xVar;
        InterfaceC0773a0 interfaceC0773a0;
        com.quizlet.features.universaluploadflow.viewmodel.a aVar3;
        kotlinx.coroutines.flow.d0 d0Var;
        final com.quizlet.features.universaluploadflow.viewmodel.a aVar4;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToWebPage, "navigateToWebPage");
        Intrinsics.checkNotNullParameter(navigateToPasteText, "navigateToPasteText");
        Intrinsics.checkNotNullParameter(navigateToFlashcards, "navigateToFlashcards");
        Intrinsics.checkNotNullParameter(navigateToPracticeTests, "navigateToPracticeTests");
        Intrinsics.checkNotNullParameter(navigateToPaywall, "navigateToPaywall");
        Intrinsics.checkNotNullParameter(navigateToLogin, "navigateToLogin");
        Intrinsics.checkNotNullParameter(navigateToSignUp, "navigateToSignUp");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(672757284);
        int i4 = i | (c0814p.f(source) ? 4 : 2) | (c0814p.h(navigateToWebPage) ? 256 : 128) | (c0814p.h(navigateToPasteText) ? 2048 : 1024) | (c0814p.h(navigateToFlashcards) ? 16384 : 8192) | (c0814p.h(navigateToLogin) ? 8388608 : 4194304) | (c0814p.h(navigateToSignUp) ? 67108864 : 33554432) | 268435456;
        if ((306783379 & i4) == 306783378 && c0814p.x()) {
            c0814p.Q();
            aVar4 = aVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.universaluploadflow.viewmodel.g.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                aVar2 = (com.quizlet.features.universaluploadflow.viewmodel.a) objE;
                i2 = i4 & (-1879048193);
            } else {
                c0814p.Q();
                aVar2 = aVar;
                i2 = i4 & (-1879048193);
            }
            c0814p.q();
            com.quizlet.features.universaluploadflow.viewmodel.g gVar = (com.quizlet.features.universaluploadflow.viewmodel.g) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(gVar.j, c0814p);
            String[] strArr = {"application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.presentationml.presentation"};
            c0814p.X(-1595295475);
            boolean zH = c0814p.h(aVar2);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (zH || objI == obj) {
                objI = new com.quizlet.features.folders.composables.J(aVar2, 18);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Function0 function0E = D5.e(strArr, (Function1) objI, c0814p);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p, 0, 7);
            kotlinx.coroutines.flow.d0 d0Var2 = gVar.k;
            c0814p.X(-1595288092);
            boolean zF = ((i2 & 896) == 256) | c0814p.f(function0E) | ((i2 & 7168) == 2048) | ((57344 & i2) == 16384) | ((29360128 & i2) == 8388608) | ((234881024 & i2) == 67108864) | c0814p.h(xVarH);
            Object objI2 = c0814p.I();
            if (zF || objI2 == obj) {
                i3 = i2;
                xVar = xVarH;
                interfaceC0773a0 = interfaceC0773a0G;
                aVar3 = aVar2;
                d0Var = d0Var2;
                objI2 = new com.quizlet.features.universaluploadflow.f(navigateBack, function0E, navigateToWebPage, navigateToPasteText, navigateToFlashcards, navigateToPracticeTests, navigateToPaywall, navigateToLogin, navigateToSignUp, xVar, null);
                c0814p.i0(objI2);
            } else {
                i3 = i2;
                interfaceC0773a0 = interfaceC0773a0G;
                xVar = xVarH;
                aVar3 = aVar2;
                d0Var = d0Var2;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            Object obj2 = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF2 = c0814p.f(obj2) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF2 || objI3 == obj) {
                objI3 = new com.quizlet.features.universaluploadflow.e(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            com.quizlet.features.universaluploadflow.data.K k = (com.quizlet.features.universaluploadflow.data.K) AbstractC4178x.k(unit, (Function2) objI3, c0814p, false, interfaceC0773a0);
            c0814p.X(-1595256984);
            com.quizlet.features.universaluploadflow.viewmodel.a aVar5 = aVar3;
            boolean zH2 = c0814p.h(aVar5);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == obj) {
                Object xVar2 = new com.quizlet.features.settings.composables.x(1, aVar5, com.quizlet.features.universaluploadflow.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/features/universaluploadflow/data/UniversalUploadFlowEvent;)V", 0, 13);
                aVar4 = aVar5;
                c0814p.i0(xVar2);
                objI4 = xVar2;
            } else {
                aVar4 = aVar5;
            }
            c0814p.p(false);
            b(k, (Function1) ((kotlin.reflect.f) objI4), c0814p, 0);
            c0814p.X(-1595248909);
            boolean zH3 = c0814p.h(aVar4);
            Object objI5 = c0814p.I();
            if (zH3 || objI5 == obj) {
                final int i5 = 0;
                objI5 = new Function0() { // from class: com.quizlet.features.universaluploadflow.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i5) {
                            case 0:
                                ((g) aVar4).D(n.a);
                                break;
                            default:
                                ((g) aVar4).D(C4463l.a);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI5);
            }
            Function0 function0 = (Function0) objI5;
            c0814p.p(false);
            c0814p.X(-1595251854);
            boolean zH4 = c0814p.h(aVar4);
            Object objI6 = c0814p.I();
            if (zH4 || objI6 == obj) {
                final int i6 = 1;
                objI6 = new Function0() { // from class: com.quizlet.features.universaluploadflow.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i6) {
                            case 0:
                                ((g) aVar4).D(n.a);
                                break;
                            default:
                                ((g) aVar4).D(C4463l.a);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            X3.a(xVar, source, null, function0, (Function0) objI6, c0814p, 8 | ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.c(source, navigateBack, navigateToWebPage, navigateToPasteText, navigateToFlashcards, navigateToPracticeTests, navigateToPaywall, navigateToLogin, navigateToSignUp, aVar4, i);
        }
    }

    public static final void e(String str, androidx.compose.ui.graphics.painter.b bVar, Function0 function0, androidx.compose.ui.n nVar, String str2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-547358991);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.h(bVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | 3072 | (c0814p.f(str2) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p.j(b)).f;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.c();
            float f = com.quizlet.ui.resources.designsystem.generated.f.h;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarC, j, androidx.compose.foundation.shape.e.a(f));
            mVar.c();
            androidx.compose.ui.q qVarL = AbstractC0460p.l(androidx.compose.ui.draw.g.c(qVarF, androidx.compose.foundation.shape.e.a(f)), false, null, function0, 7);
            mVar.w();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarL, com.quizlet.ui.resources.designsystem.generated.j.f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
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
            AbstractC3578a5.a(bVar, str, null, null, false, C4076a.e, null, 0L, c0814p, ((i2 >> 3) & 14) | ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND), 220);
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(str, null, jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).j, c0814p, i2 & 14, 0, 65530);
            c0814p = c0814p;
            c0814p.X(-678861950);
            if (str2 != null) {
                long jF2 = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b2)).o;
                mVar.u();
                androidx.compose.material3.Q4.b(str2, AbstractC0382e.y(nVar3, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), jF2, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, (i2 >> 12) & 14, 0, 65528);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(str, bVar, function0, nVar2, str2, i, 13);
        }
    }

    public static void f(int i, int i2) {
        String strB;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strB = O3.b("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strB = O3.b("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strB);
        }
    }

    public static void g(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? h(i, i3, "start index") : (i2 < 0 || i2 > i3) ? h(i2, i3, "end index") : O3.b("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static String h(int i, int i2, String str) {
        if (i < 0) {
            return O3.b("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return O3.b("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }
}
