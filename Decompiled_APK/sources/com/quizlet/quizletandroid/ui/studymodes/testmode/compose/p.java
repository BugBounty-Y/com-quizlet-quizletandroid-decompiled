package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import android.content.Context;
import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L6;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class p {
    public static final void a(DiagramData diagramData, DBDiagramShape dBDiagramShape, DBDiagramShape dBDiagramShape2, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        DiagramData diagramDataA;
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-95543673);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(diagramData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dBDiagramShape) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dBDiagramShape2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = C0804k.a;
            if (dBDiagramShape == null || dBDiagramShape2 == null) {
                diagramDataA = diagramData;
            } else {
                DiagramData.Builder builderA = diagramData.a();
                builderA.b(B.j(dBDiagramShape2, dBDiagramShape));
                diagramDataA = builderA.a();
            }
            c0814p.X(-1113093233);
            Object objB = K6.b(com.quizlet.diagrams.ui.b.class, ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getApplicationContext());
            c0814p.p(false);
            DiagramJSBridge diagramJSBridge = new DiagramJSBridge(((u) ((com.quizlet.diagrams.ui.b) objB)).V());
            androidx.compose.ui.q qVarC = K0.c(qVar, 1.0f);
            com.quizlet.themes.m.g.e.getClass();
            androidx.compose.ui.q qVarE = K0.e(qVarC, com.quizlet.ui.resources.designsystem.generated.h.e, com.quizlet.themes.m.D0);
            c0814p.X(-1258295973);
            boolean zH = ((i2 & 57344) == 16384) | c0814p.h(diagramJSBridge);
            Object objI = c0814p.I();
            if (zH || objI == obj) {
                objI = new v(3, function1, diagramJSBridge);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            L6.a(diagramDataA, qVarE, null, true, null, diagramJSBridge, null, (Function0) objI, c0814p, 265216, 84);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(diagramData, dBDiagramShape, dBDiagramShape2, qVar, function1, i, 19);
        }
    }
}
