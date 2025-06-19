package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import java.util.Arrays;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class n3 {
    /* JADX WARN: Removed duplicated region for block: B:114:0x02fc  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0362  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x038f  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0395  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x03b3  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x03df  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0466  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r40, com.quizlet.features.questiontypes.selfassessment.data.a r41, kotlin.jvm.functions.Function0 r42, com.quizlet.features.questiontypes.basequestion.i r43, com.quizlet.features.questiontypes.selfassessment.h r44, androidx.compose.ui.q r45, androidx.compose.runtime.InterfaceC0806l r46, int r47) {
        /*
            Method dump skipped, instructions count: 1242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.n3.a(int, com.quizlet.features.questiontypes.selfassessment.data.a, kotlin.jvm.functions.Function0, com.quizlet.features.questiontypes.basequestion.i, com.quizlet.features.questiontypes.selfassessment.h, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.questiontypes.basequestion.i iVar, com.quizlet.features.questiontypes.selfassessment.h hVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(746159820);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(iVar) : c0814p.h(iVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(hVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            c0814p.X(-735924496);
            boolean zH = ((i2 & 14) == 4 || ((i2 & 8) != 0 && c0814p.h(iVar))) | c0814p.h(j) | c0814p.h(hVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.lifecycle.compose.d(j, iVar, hVar, 18);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.d(j, (Function1) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(iVar, hVar, i, 20);
        }
    }

    public static final void c(int i, com.quizlet.features.questiontypes.basequestion.i questionViewModel, androidx.compose.ui.q qVar, com.quizlet.features.questiontypes.selfassessment.h hVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        int i3;
        com.quizlet.features.questiontypes.selfassessment.h hVar2;
        com.quizlet.features.questiontypes.selfassessment.h hVar3;
        com.quizlet.features.questiontypes.selfassessment.h hVar4;
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1524234791);
        int i4 = i2 | (c0814p2.d(i) ? 4 : 2) | (c0814p2.f(questionViewModel) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128) | 1024;
        if ((i4 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            hVar4 = hVar;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                c0814p = c0814p2;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.questiontypes.selfassessment.h.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.questiontypes.selfassessment.h hVar5 = (com.quizlet.features.questiontypes.selfassessment.h) w0VarE;
                i3 = i4 & (-7169);
                hVar2 = hVar5;
            } else {
                c0814p2.Q();
                i3 = i4 & (-7169);
                c0814p = c0814p2;
                hVar2 = hVar;
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(hVar2.i, c0814p);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(hVar2.k, c0814p);
            com.quizlet.features.questiontypes.selfassessment.data.c cVar = (com.quizlet.features.questiontypes.selfassessment.data.c) interfaceC0773a0M.getValue();
            if (Intrinsics.b(cVar, com.quizlet.features.questiontypes.selfassessment.data.b.a)) {
                c0814p.X(-735880988);
                C0814p c0814p3 = c0814p;
                AbstractC3249r5.a(null, 0L, c0814p3, 0, 3);
                c0814p = c0814p3;
                c0814p.p(false);
                hVar3 = hVar2;
            } else {
                if (!(cVar instanceof com.quizlet.features.questiontypes.selfassessment.data.a)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-735882344, c0814p, false);
                }
                c0814p.X(-735878196);
                com.quizlet.features.questiontypes.selfassessment.data.c cVar2 = (com.quizlet.features.questiontypes.selfassessment.data.c) interfaceC0773a0M.getValue();
                Intrinsics.e(cVar2, "null cannot be cast to non-null type com.quizlet.features.questiontypes.selfassessment.data.SelfAssessmentUiState.FlashcardViewState");
                com.quizlet.features.questiontypes.selfassessment.data.a aVar = (com.quizlet.features.questiontypes.selfassessment.data.a) cVar2;
                c0814p.X(-735872247);
                boolean zF = c0814p.f(interfaceC0773a0M2);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a0M2, 8);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                int i5 = (i3 & 14) | ((i3 << 6) & 7168) | ((i3 << 9) & 458752);
                hVar3 = hVar2;
                a(i, aVar, (Function0) objI, questionViewModel, hVar3, qVar, c0814p, i5);
                c0814p.p(false);
            }
            hVar4 = hVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, i2, 1, questionViewModel, qVar, hVar4);
        }
    }

    public static final com.airbnb.lottie.parser.l d(kmppUtils.bitmasks.a... enumValues) {
        Intrinsics.checkNotNullParameter(enumValues, "enumValues");
        kmppUtils.bitmasks.a[] others = (kmppUtils.bitmasks.a[]) Arrays.copyOf(enumValues, enumValues.length);
        Intrinsics.checkNotNullParameter(others, "others");
        int iA = 0;
        for (kmppUtils.bitmasks.a aVar : others) {
            iA |= aVar.a();
        }
        return new com.airbnb.lottie.parser.l(iA, 14);
    }
}
