package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.data.model.ReviewSheetInfo;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class I6 {
    public static final void a(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g gVar, LearnSettingsGradingUpdateData learnSettingsGradingUpdateData, Function1 function1, Function1 function12, Function1 function13, Function0 function0, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        androidx.compose.ui.n nVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(292068201);
        int i2 = i | (c0814p.f(gVar) ? 4 : 2) | (c0814p.f(learnSettingsGradingUpdateData) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function13) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536) | (c0814p.f(qVar) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = qVar.g(androidx.compose.foundation.layout.K0.c);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.q qVarU = AbstractC0460p.u(AbstractC0382e.u(qVarG, com.quizlet.ui.resources.designsystem.generated.j.h), AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            c0814p.X(1282310541);
            c0814p.p(false);
            c0814p.X(1282325727);
            boolean z2 = gVar.f;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (z2) {
                String strD = AbstractC3106b5.d(c0814p, R.string.grading_options_flexible_grading);
                boolean z3 = learnSettingsGradingUpdateData.b;
                String strD2 = AbstractC3106b5.d(c0814p, R.string.grading_options_flexible_grading_description);
                mVar.q();
                z = false;
                d(strD, z3, function12, strD2, "switch_partial_answers", AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i2 >> 3) & 896) | 24576, 0);
            } else {
                z = false;
            }
            c0814p.p(z);
            c0814p.X(1282344453);
            if (gVar.e) {
                String strD3 = AbstractC3106b5.d(c0814p, R.string.assistant_settings_grading_options_smart_grading);
                boolean z4 = learnSettingsGradingUpdateData.c;
                String strD4 = AbstractC3106b5.d(c0814p, R.string.grading_options_smart_grading_description);
                mVar.q();
                nVar = nVar2;
                d(strD3, z4, function13, strD4, "switch_smart_grading", AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i2 >> 6) & 896) | 24576, 0);
            } else {
                nVar = nVar2;
            }
            c0814p.p(z);
            c0814p.X(1282363234);
            if (gVar.d) {
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
                String strD5 = AbstractC3106b5.d(c0814p, R.string.grading_options_smart_grading_provide_feedback);
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                mVar.q();
                AbstractC3586b5.a(strD5, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0, false, null, null, null, null, null, c0814p, (i2 >> 9) & 896, 1016);
                c0814p = c0814p;
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(gVar, learnSettingsGradingUpdateData, function1, function12, function13, function0, qVar, i, 7);
        }
    }

    public static final void b(Function0 navigateBack, Function0 navigateToProvideFeedbackUrl, androidx.compose.ui.q qVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        int i2;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a aVar2;
        boolean z;
        androidx.compose.ui.q qVar3;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a aVar3;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToProvideFeedbackUrl, "navigateToProvideFeedbackUrl");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(159845219);
        int i3 = i | (c0814p2.h(navigateBack) ? 4 : 2) | (c0814p2.h(navigateToProvideFeedbackUrl) ? 32 : 16) | 1408;
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            qVar3 = qVar;
            aVar3 = aVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                qVar2 = androidx.compose.ui.n.b;
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                c0814p = c0814p2;
                Object objE = AbstractC3417z1.e(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-7169);
                aVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a) objE;
            } else {
                c0814p2.Q();
                i2 = i3 & (-7169);
                qVar2 = qVar;
                aVar2 = aVar;
                c0814p = c0814p2;
            }
            c0814p.q();
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g gVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(gVar.h, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = gVar.i;
            c0814p.X(1605165732);
            boolean z2 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 14) == 4);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z2 || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.d(navigateBack, navigateToProvideFeedbackUrl, null);
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
                objI2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "learn_settings_grading");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i) interfaceC0773a0G.getValue();
            if (iVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g) {
                c0814p.X(229384108);
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i iVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i) interfaceC0773a0G.getValue();
                Intrinsics.e(iVar2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUiState.Content");
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g gVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g) iVar2;
                c0814p.X(229386946);
                boolean zH = c0814p.h(aVar2);
                Object objI3 = c0814p.I();
                if (zH || objI3 == v) {
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, aVar2, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/settings/grading/data/LearnSettingsGradingEvent;)V", 0, 4);
                    c0814p.i0(yVar);
                    objI3 = yVar;
                }
                c0814p.p(false);
                c(gVar2, (Function1) ((kotlin.reflect.f) objI3), c0814p, 0);
                c0814p.p(false);
                z = true;
            } else {
                if (!Intrinsics.b(iVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.h.a)) {
                    throw com.google.android.gms.measurement.internal.Z.j(229382073, c0814p, false);
                }
                c0814p.X(229389751);
                z = true;
                C0814p c0814p3 = c0814p;
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p3, 0, 1);
                c0814p = c0814p3;
                c0814p.p(false);
            }
            c0814p.p(z);
            qVar3 = qVar2;
            aVar3 = aVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(navigateBack, navigateToProvideFeedbackUrl, qVar3, aVar3, i, 5);
        }
    }

    public static final void c(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g gVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        int i2 = 0;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-575379967);
        int i3 = (c0814p2.f(gVar) ? 4 : 2) | i | (c0814p2.h(function1) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(161568658);
            boolean z = (i3 & 14) == 4;
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(gVar, i2);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p2, 0, 6);
            c0814p2.X(161578869);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.tag.composable.f(11, interfaceC0773a0, function1);
                c0814p2.i0(objI2);
            }
            Function0 function0 = (Function0) objI2;
            c0814p2.p(false);
            androidx.work.impl.t.a(false, function0, c0814p2, 48, 1);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-829411651, new com.quizlet.features.practicetest.results.i(24, gVar, function0), c0814p2);
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, dVarE, null, null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1760775406, new com.quizlet.assembly.compose.input.h(26, gVar, interfaceC0773a0, function1, false), c0814p2), c0814p, 805306416, 253);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(gVar, function1, i, 25);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:73:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(java.lang.String r30, boolean r31, kotlin.jvm.functions.Function1 r32, java.lang.String r33, java.lang.String r34, androidx.compose.ui.q r35, androidx.compose.runtime.InterfaceC0806l r36, int r37, int r38) {
        /*
            Method dump skipped, instructions count: 347
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.I6.d(java.lang.String, boolean, kotlin.jvm.functions.Function1, java.lang.String, java.lang.String, androidx.compose.ui.q, androidx.compose.runtime.l, int, int):void");
    }

    public static final boolean e(com.quizlet.data.model.R1 r1) {
        return r1 != null && r1.a() == EnumC4175w.ERROR;
    }

    public static final boolean f(NotesToValueInfo notesToValueInfo) {
        Intrinsics.checkNotNullParameter(notesToValueInfo, "<this>");
        EssayInfo essayInfo = notesToValueInfo.g;
        EnumC4175w enumC4175w = essayInfo != null ? essayInfo.b : null;
        EnumC4175w enumC4175w2 = EnumC4175w.MODERATION;
        if (enumC4175w != enumC4175w2) {
            return false;
        }
        OutlineMarkdownInfo outlineMarkdownInfo = notesToValueInfo.d;
        if ((outlineMarkdownInfo != null ? outlineMarkdownInfo.b : null) != enumC4175w2) {
            return false;
        }
        ReviewSheetInfo reviewSheetInfo = notesToValueInfo.e;
        if ((reviewSheetInfo != null ? reviewSheetInfo.b : null) != enumC4175w2) {
            return false;
        }
        FlashcardsInfo flashcardsInfo = notesToValueInfo.f;
        return (flashcardsInfo != null ? flashcardsInfo.b : null) == enumC4175w2;
    }
}
