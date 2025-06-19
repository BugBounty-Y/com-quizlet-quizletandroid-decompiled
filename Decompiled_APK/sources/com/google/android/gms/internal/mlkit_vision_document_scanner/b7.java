package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b7 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:20:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.quizletandroid.ui.studymodes.testmode.models.p r9, androidx.compose.ui.q r10, androidx.compose.runtime.InterfaceC0806l r11, int r12) {
        /*
            r5 = r11
            androidx.compose.runtime.p r5 = (androidx.compose.runtime.C0814p) r5
            r11 = 61385732(0x3a8ac04, float:9.913645E-37)
            r5.Z(r11)
            boolean r11 = r5.h(r9)
            if (r11 == 0) goto L11
            r11 = 4
            goto L12
        L11:
            r11 = 2
        L12:
            r11 = r11 | r12
            boolean r0 = r5.f(r10)
            if (r0 == 0) goto L1c
            r0 = 32
            goto L1e
        L1c:
            r0 = 16
        L1e:
            r11 = r11 | r0
            r0 = r11 & 19
            r1 = 18
            if (r0 != r1) goto L31
            boolean r0 = r5.x()
            if (r0 != 0) goto L2c
            goto L31
        L2c:
            r5.Q()
            r3 = r10
            goto L83
        L31:
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g r0 = r9.d
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f r0 = r0.b
            com.quizlet.db.data.models.persisted.DBDiagramShape r1 = r0.a()
            com.quizlet.studiablemodels.LocationQuestionSectionData r2 = r9.b
            long r3 = r2.a
            boolean r6 = r0.a
            boolean r6 = com.bumptech.glide.b.c(r6)
            com.quizlet.db.data.models.persisted.DBDiagramShape r0 = r0.a()
            com.quizlet.db.data.models.persisted.DBDiagramShape r2 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5.b(r2)
            r7 = 2055443777(0x7a839541, float:3.4160906E35)
            r5.X(r7)
            boolean r7 = r5.h(r1)
            boolean r8 = r5.e(r3)
            r7 = r7 | r8
            boolean r8 = r5.g(r6)
            r7 = r7 | r8
            java.lang.Object r8 = r5.I()
            if (r7 != 0) goto L69
            androidx.compose.runtime.V r7 = androidx.compose.runtime.C0804k.a
            if (r8 != r7) goto L71
        L69:
            com.quizlet.quizletandroid.ui.studymodes.testmode.compose.q r8 = new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.q
            r8.<init>()
            r5.i0(r8)
        L71:
            r4 = r8
            kotlin.jvm.functions.Function1 r4 = (kotlin.jvm.functions.Function1) r4
            r1 = 0
            r5.p(r1)
            int r11 = r11 << 6
            r6 = r11 & 7168(0x1c00, float:1.0045E-41)
            r1 = r0
            com.quizlet.studiablemodels.diagrams.DiagramData r0 = r9.c
            r3 = r10
            com.quizlet.quizletandroid.ui.studymodes.testmode.compose.p.a(r0, r1, r2, r3, r4, r5, r6)
        L83:
            androidx.compose.runtime.o0 r10 = r5.r()
            if (r10 == 0) goto L92
            com.quizlet.features.questionnaire.screens.d r11 = new com.quizlet.features.questionnaire.screens.d
            r0 = 27
            r11.<init>(r9, r3, r12, r0)
            r10.d = r11
        L92:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.b7.a(com.quizlet.quizletandroid.ui.studymodes.testmode.models.p, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void b(f7 promptConfig, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(promptConfig, "promptConfig");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1363856418);
        int i2 = (c0814p.f(promptConfig) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else if (promptConfig instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.p) {
            c0814p.X(1934113755);
            a((com.quizlet.quizletandroid.ui.studymodes.testmode.models.p) promptConfig, androidx.compose.ui.platform.N.G(qVar, "test_location_diagram"), c0814p, 0);
            c0814p.p(false);
        } else {
            if (!(promptConfig instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.o)) {
                throw com.google.android.gms.measurement.internal.Z.j(893673043, c0814p, false);
            }
            c0814p.X(1934367893);
            com.quizlet.quizletandroid.ui.studymodes.testmode.models.o oVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.o) promptConfig;
            c7.b(oVar.b, oVar.c, qVar, function1, c0814p, (i2 << 3) & 8064);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 8, promptConfig, qVar, function1);
        }
    }
}
