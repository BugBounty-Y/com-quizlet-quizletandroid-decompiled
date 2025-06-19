package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableDiagramShape;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes2.dex */
public abstract class k7 {
    public static final void a(com.quizlet.explanations.questiondetail.viewmodel.f viewModel, androidx.compose.ui.n nVar, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, Function0 function0, Function1 function1, androidx.compose.material3.O3 o3, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar3;
        androidx.compose.material3.O3 o32;
        androidx.compose.ui.n nVar4;
        androidx.compose.material3.O3 o33;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar5;
        androidx.compose.ui.n nVar6;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-345284193);
        if (((i | (c0814p.h(viewModel) ? 4 : 2) | 176 | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192) | 196608) & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar6 = nVar;
            nVar5 = nVar2;
            o33 = o3;
        } else {
            c0814p.S();
            int i2 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i2 == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar7 = androidx.compose.ui.n.b;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.infra.folder.menu.viewmodel.a.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                nVar3 = (com.quizlet.features.infra.folder.menu.viewmodel.n) objE;
                c0814p.X(1757487393);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new androidx.compose.material3.O3();
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                o32 = (androidx.compose.material3.O3) objI;
                nVar4 = nVar7;
            } else {
                c0814p.Q();
                nVar4 = nVar;
                nVar3 = nVar2;
                o32 = o3;
            }
            c0814p.q();
            InterfaceC4992i interfaceC4992iU = nVar3.u();
            c0814p.X(1757491055);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.explanations.questiondetail.ui.composables.h(o32, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(interfaceC4992iU) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new com.quizlet.explanations.questiondetail.ui.composables.g(interfaceC0773a0D, j, null, interfaceC4992iU);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            com.quizlet.features.infra.folder.menu.viewmodel.n nVar8 = nVar3;
            AbstractC0725t3.a(nVar4, androidx.compose.runtime.internal.e.e(1341363291, new com.quizlet.assembly.compose.buttons.A((Object) viewModel, (Object) nVar8, (Object) function0, C0776c.m(viewModel.z, c0814p), 2), c0814p), null, androidx.compose.runtime.internal.e.e(-611186663, new com.quizlet.explanations.questiondetail.ui.composables.j(o32, nVar8, 0), c0814p), null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(476476464, new com.quizlet.assembly.compose.input.m(1, viewModel, function1), c0814p), c0814p, 805309494, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
            c0814p = c0814p;
            o33 = o32;
            nVar5 = nVar8;
            nVar6 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(viewModel, nVar6, nVar5, function0, function1, o33, i, 0);
        }
    }

    public static com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b(QuestionSectionData questionSectionData, boolean z) {
        Long lValueOf;
        StudiableDiagramShape studiableDiagramShape;
        StudiableText studiableText;
        StudiableImage studiableImage;
        StudiableAudio studiableAudio;
        if (questionSectionData instanceof DefaultQuestionSectionData) {
            DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
            StudiableText studiableText2 = defaultQuestionSectionData.a;
            StudiableImage studiableImage2 = defaultQuestionSectionData.b;
            studiableAudio = defaultQuestionSectionData.c;
            studiableText = studiableText2;
            studiableDiagramShape = null;
            lValueOf = null;
            studiableImage = studiableImage2;
        } else {
            if (!(questionSectionData instanceof LocationQuestionSectionData)) {
                throw new NoWhenBranchMatchedException();
            }
            LocationQuestionSectionData locationQuestionSectionData = (LocationQuestionSectionData) questionSectionData;
            StudiableDiagramShape studiableDiagramShape2 = locationQuestionSectionData.b;
            lValueOf = Long.valueOf(locationQuestionSectionData.a);
            studiableDiagramShape = studiableDiagramShape2;
            studiableText = null;
            studiableImage = null;
            studiableAudio = null;
        }
        return new com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f(z, studiableText, studiableImage, studiableAudio, studiableDiagramShape, lValueOf);
    }
}
