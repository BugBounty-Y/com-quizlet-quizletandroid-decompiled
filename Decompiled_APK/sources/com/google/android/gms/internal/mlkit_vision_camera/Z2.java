package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0409s;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.studiablemodels.StudiableImage;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z2 {
    public static final void a(com.quizlet.features.questiontypes.basequestion.i questionViewModel, androidx.compose.ui.q qVar, com.quizlet.features.questiontypes.mcq.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.questiontypes.mcq.a aVar2;
        Object aVar3;
        com.quizlet.features.questiontypes.mcq.data.d dVar;
        androidx.compose.runtime.V v;
        InterfaceC0773a0 interfaceC0773a0;
        Function0 function0;
        StudiableImage studiableImage;
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1718369453);
        int i3 = i | (c0814p.f(questionViewModel) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
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
                Object objE = AbstractC3417z1.e(com.quizlet.features.questiontypes.mcq.l.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p = c0814p;
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-897);
                aVar2 = (com.quizlet.features.questiontypes.mcq.a) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.features.questiontypes.mcq.l lVar = (com.quizlet.features.questiontypes.mcq.l) aVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(lVar.p, c0814p);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(lVar.t, c0814p);
            com.quizlet.features.questiontypes.mcq.o oVar = (com.quizlet.features.questiontypes.mcq.o) interfaceC0773a0M.getValue();
            if (oVar instanceof com.quizlet.features.questiontypes.mcq.m) {
                c0814p.X(-663176719);
                AbstractC3249r5.a(qVar, 0L, c0814p, (i2 >> 3) & 14, 2);
                c0814p.p(false);
                aVar = aVar2;
            } else {
                if (!(oVar instanceof com.quizlet.features.questiontypes.mcq.n)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1683957199, c0814p, false);
                }
                c0814p.X(-662899548);
                com.quizlet.features.questiontypes.mcq.o oVar2 = (com.quizlet.features.questiontypes.mcq.o) interfaceC0773a0M.getValue();
                Intrinsics.e(oVar2, "null cannot be cast to non-null type com.quizlet.features.questiontypes.mcq.MultipleChoiceUiState.ViewState");
                com.quizlet.features.questiontypes.mcq.data.d dVar2 = ((com.quizlet.features.questiontypes.mcq.n) oVar2).a;
                N2 n2 = dVar2.a;
                com.quizlet.features.questiontypes.data.d dVar3 = n2 instanceof com.quizlet.features.questiontypes.data.d ? (com.quizlet.features.questiontypes.data.d) n2 : null;
                com.quizlet.features.questiontypes.data.b bVar = n2 instanceof com.quizlet.features.questiontypes.data.b ? (com.quizlet.features.questiontypes.data.b) n2 : null;
                c0814p.X(-1683946507);
                Object objI = c0814p.I();
                androidx.compose.runtime.V v2 = C0804k.a;
                if (objI == v2) {
                    objI = C0776c.z(Boolean.FALSE);
                    c0814p.i0(objI);
                }
                InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
                c0814p.p(false);
                com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p, 48, 5);
                com.quizlet.features.questiontypes.basequestion.data.a aVar4 = (com.quizlet.features.questiontypes.basequestion.data.a) interfaceC0773a0M2.getValue();
                c0814p.X(-1683936923);
                Object objI2 = c0814p.I();
                if (objI2 == v2) {
                    objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 13);
                    c0814p.i0(objI2);
                }
                Function1 function1 = (Function1) objI2;
                c0814p.p(false);
                c0814p.X(-1683935230);
                boolean zH = c0814p.h(aVar2);
                Object objI3 = c0814p.I();
                if (zH || objI3 == v2) {
                    objI3 = new com.quizlet.features.questiontypes.mcq.ui.d(aVar2, 0);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                C0814p c0814p2 = c0814p;
                C2.a(dVar2.d, aVar4, function1, (Function0) objI3, c0814p2, 384);
                c0814p2.X(-1683931311);
                boolean zH2 = c0814p2.h(aVar2);
                Object objI4 = c0814p2.I();
                if (zH2 || objI4 == v2) {
                    dVar = dVar2;
                    v = v2;
                    interfaceC0773a0 = interfaceC0773a02;
                    aVar3 = new com.quizlet.features.notes.paywall.a(0, aVar2, com.quizlet.features.questiontypes.mcq.a.class, "logQuestionStart", "logQuestionStart()V", 0, 11);
                    c0814p2.i0(aVar3);
                } else {
                    aVar3 = objI4;
                    dVar = dVar2;
                    v = v2;
                    interfaceC0773a0 = interfaceC0773a02;
                }
                c0814p2.p(false);
                Function0 function02 = (Function0) ((kotlin.reflect.f) aVar3);
                c0814p2.X(-1683929488);
                boolean zH3 = c0814p2.h(aVar2);
                Object objI5 = c0814p2.I();
                if (zH3 || objI5 == v) {
                    function0 = function02;
                    com.quizlet.features.notes.paywall.a aVar5 = new com.quizlet.features.notes.paywall.a(0, aVar2, com.quizlet.features.questiontypes.mcq.a.class, "logQuestionStop", "logQuestionStop()V", 0, 12);
                    c0814p2.i0(aVar5);
                    objI5 = aVar5;
                } else {
                    function0 = function02;
                }
                c0814p2.p(false);
                J2.a(function0, (Function0) ((kotlin.reflect.f) objI5), c0814p2, 0);
                K2.a(lVar.v, questionViewModel, c0814p2, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND);
                androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
                int i4 = c0814p2.P;
                InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
                androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i = C0914j.b;
                c0814p2.b0();
                if (c0814p2.O) {
                    c0814p2.k(c0913i);
                } else {
                    c0814p2.l0();
                }
                C0776c.E(c0814p2, kE, C0914j.f);
                C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
                C0912h c0912h = C0914j.g;
                if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                    android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
                }
                C0776c.E(c0814p2, qVarC, C0914j.d);
                com.quizlet.features.questiontypes.data.d dVar4 = dVar3;
                aVar = aVar2;
                AbstractC0725t3.a(null, null, androidx.compose.runtime.internal.e.e(-1624254079, new com.quizlet.features.practicetest.results.i(2, interfaceC0773a0, aVar2), c0814p2), null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(-250805257, new com.quizlet.features.blocks.ui.d(dVar, aVar2, dVar.b, bVar, xVarH, dVar4, 3), c0814p2), c0814p2, 805306752, 507);
                c0814p = c0814p2;
                Z5.c((dVar4 == null || (studiableImage = dVar4.b) == null) ? null : studiableImage.a(), null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
                c0814p.p(true);
                c0814p.p(false);
            }
        }
        com.quizlet.features.questiontypes.mcq.a aVar6 = aVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 6, qVar, (Object) questionViewModel, (Object) aVar6);
        }
    }

    public static kotlinx.serialization.json.q b(androidx.camera.camera2.internal.p0 p0Var) {
        return Y1.c(new androidx.compose.animation.T(p0Var, true));
    }

    public static Set c(assistantMode.tasks.progress.b bVar, assistantMode.enums.k questionType) {
        bVar.getClass();
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        assistantMode.tasks.progress.a aVar = (assistantMode.tasks.progress.a) bVar.c.get(questionType);
        if (aVar != null) {
            LinkedHashSet linkedHashSet = aVar.d;
            Set setA0 = CollectionsKt.A0(CollectionsKt.p0(linkedHashSet, linkedHashSet.size()));
            if (setA0 != null) {
                return setA0;
            }
        }
        return kotlin.collections.M.a;
    }
}
