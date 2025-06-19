package com.google.android.gms.internal.mlkit_vision_common;

import android.graphics.Typeface;
import androidx.compose.foundation.layout.C0393j0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.data.model.AbstractC4178x;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.e4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3448e4 {
    /* JADX WARN: Removed duplicated region for block: B:90:0x0251  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0253  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0262  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.lang.String r34, com.quizlet.features.universaluploadflow.pastetext.data.m r35, kotlin.jvm.functions.Function0 r36, kotlin.jvm.functions.Function1 r37, kotlin.jvm.functions.Function1 r38, androidx.compose.ui.q r39, androidx.compose.runtime.InterfaceC0806l r40, int r41) {
        /*
            Method dump skipped, instructions count: 653
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4.a(java.lang.String, com.quizlet.features.universaluploadflow.pastetext.data.m, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.universaluploadflow.pastetext.data.p pVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Object iVar;
        InterfaceC0773a0 interfaceC0773a0;
        InterfaceC0773a0 interfaceC0773a02;
        com.quizlet.features.universaluploadflow.pastetext.data.p pVar2 = pVar;
        Function1 function12 = function1;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1652898246);
        int i2 = (c0814p.f(pVar2) ? 4 : 2) | i | (c0814p.h(function12) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(115973120);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(13);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            c0814p.X(115974956);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI2);
            }
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) objI2;
            Object objG = com.google.android.gms.measurement.internal.Z.g(115977516, c0814p, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(115979532, c0814p, false);
            if (objG2 == v) {
                objG2 = C0776c.z(Boolean.FALSE);
                c0814p.i0(objG2);
            }
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) objG2;
            c0814p.p(false);
            Boolean bool = (Boolean) interfaceC0773a06.getValue();
            bool.booleanValue();
            c0814p.X(115982236);
            int i3 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z = i3 == 32;
            Object objI3 = c0814p.I();
            if (z || objI3 == v) {
                objI3 = new com.quizlet.features.universaluploadflow.pastetext.b(interfaceC0773a06, null, function12);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.g(bool, function12, (Function2) objI3, c0814p);
            c0814p.X(115986945);
            boolean zF = ((i2 & 14) == 4) | c0814p.f(interfaceC0773a03) | (i3 == 32);
            Object objI4 = c0814p.I();
            if (zF || objI4 == v) {
                interfaceC0773a0 = interfaceC0773a04;
                iVar = new com.braze.communication.i(pVar2, function12, interfaceC0773a05, interfaceC0773a03, interfaceC0773a0, 3);
                interfaceC0773a02 = interfaceC0773a03;
                c0814p.i0(iVar);
            } else {
                iVar = objI4;
                interfaceC0773a02 = interfaceC0773a03;
                interfaceC0773a0 = interfaceC0773a04;
            }
            Function0 function0 = (Function0) iVar;
            c0814p.p(false);
            androidx.work.impl.t.a(false, function0, c0814p, 0, 1);
            pVar2 = pVar;
            function12 = function1;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.a.a(androidx.compose.ui.n.b, new C0393j0(3, 7)), "PasteText"), androidx.compose.runtime.internal.e.e(-1693225986, new com.quizlet.explanations.questiondetail.ui.composables.m(21, function0), c0814p), null, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(73176457, new com.quizlet.features.blocks.ui.d(pVar2, function12, interfaceC0773a02, interfaceC0773a06, interfaceC0773a05, interfaceC0773a0, 5), c0814p), c0814p, 805306416, 508);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(pVar2, function12, i, 13);
        }
    }

    public static final void c(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1065225516);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            function02 = function0;
            AbstractC3691o6.c(null, null, jG, 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function02, null, null, c0814p, (i2 << 15) & 458752, 203);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 10, function02);
        }
    }

    public static final void d(Function0 navigateBack, Function0 navigateClose, Function1 navigateToPracticeTests, Function0 navigateToPaywall, com.quizlet.features.universaluploadflow.pastetext.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.universaluploadflow.pastetext.viewmodel.a aVar2;
        com.quizlet.features.universaluploadflow.pastetext.viewmodel.a aVar3;
        com.quizlet.features.universaluploadflow.pastetext.viewmodel.a aVar4;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateClose, "navigateClose");
        Intrinsics.checkNotNullParameter(navigateToPracticeTests, "navigateToPracticeTests");
        Intrinsics.checkNotNullParameter(navigateToPaywall, "navigateToPaywall");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(803435108);
        int i3 = i | (c0814p.h(navigateBack) ? 4 : 2) | 8192;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
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
                Object objE = AbstractC3417z1.e(com.quizlet.features.universaluploadflow.pastetext.viewmodel.d.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-57345);
                aVar2 = (com.quizlet.features.universaluploadflow.pastetext.viewmodel.a) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-57345);
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.features.universaluploadflow.pastetext.viewmodel.d dVar = (com.quizlet.features.universaluploadflow.pastetext.viewmodel.d) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(dVar.d, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = dVar.e;
            c0814p.X(-1301374362);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.universaluploadflow.pastetext.e(navigateBack, navigateClose, navigateToPracticeTests, navigateToPaywall, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.features.universaluploadflow.pastetext.d(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.features.universaluploadflow.pastetext.data.p pVar = (com.quizlet.features.universaluploadflow.pastetext.data.p) AbstractC4178x.k(unit, (Function2) objI2, c0814p, false, interfaceC0773a0G);
            c0814p.X(-1301359902);
            boolean zH = c0814p.h(aVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                aVar3 = aVar2;
                com.quizlet.features.settings.composables.x xVar = new com.quizlet.features.settings.composables.x(1, aVar3, com.quizlet.features.universaluploadflow.pastetext.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/features/universaluploadflow/pastetext/data/UniversalUploadFlowPasteTextEvent;)V", 0, 18);
                c0814p.i0(xVar);
                objI3 = xVar;
            } else {
                aVar3 = aVar2;
            }
            c0814p.p(false);
            b(pVar, (Function1) ((kotlin.reflect.f) objI3), c0814p, 0);
            aVar4 = aVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(navigateBack, navigateClose, (InterfaceC4938g) navigateToPracticeTests, (InterfaceC4938g) navigateToPaywall, (Object) aVar4, i, 15);
        }
    }

    public abstract void e(int i);

    public abstract void f(Typeface typeface, boolean z);
}
