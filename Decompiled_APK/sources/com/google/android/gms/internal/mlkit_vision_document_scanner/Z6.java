package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.quizletandroid.ui.studymodes.testmode.models.m mVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1335910872);
        int i2 = (c0814p.h(mVar) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f fVar = mVar.b;
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f fVar2 = mVar.d;
            DBDiagramShape dBDiagramShapeA = fVar2.a();
            DBDiagramShape dBDiagramShapeA2 = fVar.a();
            c0814p.X(723177759);
            boolean zH = c0814p.h(fVar2) | c0814p.h(fVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.header.ui.g(27, fVar2, fVar);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            qVar2 = qVar;
            com.quizlet.quizletandroid.ui.studymodes.testmode.compose.p.a(mVar.c, dBDiagramShapeA, dBDiagramShapeA2, qVar2, (Function1) objI, c0814p, (i2 << 6) & 7168);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(mVar, qVar2, i, 26);
        }
    }

    public static final void b(e7 config, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(config, "config");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-750780608);
        int i2 = (c0814p.f(config) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else if (config instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.m) {
            c0814p.X(-2129252523);
            a((com.quizlet.quizletandroid.ui.studymodes.testmode.models.m) config, androidx.compose.ui.platform.N.G(qVar, "test_answer_diagram"), c0814p, 0);
            c0814p.p(false);
        } else {
            if (!(config instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.n) && !(config instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.l)) {
                throw com.google.android.gms.measurement.internal.Z.j(-1869802608, c0814p, false);
            }
            c0814p.X(-2128935238);
            W6.b(config, qVar, function1, c0814p, i2 & 1022);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 7, config, qVar, function1);
        }
    }
}
