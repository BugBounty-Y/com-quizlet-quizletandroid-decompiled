package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.ui.library.data.C4647a;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.y4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3768y4 {
    public static final void a(C4647a classData, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(classData, "classData");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1387293145);
        int i2 = i | (c0814p2.f(classData) ? 4 : 2) | 48 | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            c0814p2.X(2096948207);
            boolean z = ((i2 & 896) == 256) | ((i2 & 14) == 4);
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.questionnaire.screens.c(22, function1, classData);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            R4.a(qVarC, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-1904983379, new com.quizlet.assembly.compose.cards.c(classData, 27), c0814p2), c0814p, 0, 990);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 26, classData, nVar2, function1);
        }
    }

    public static ArrayList b() {
        ArrayList arrayList = new ArrayList();
        arrayList.add("");
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.f fVar2 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar.g;
        int i = fVar2 == null ? -1 : com.perimeterx.mobile_sdk.doctor_app.ui.g.a[fVar2.ordinal()];
        arrayList.addAll(i != 1 ? i != 2 ? new ArrayList() : com.perimeterx.mobile_sdk.doctor_app.ui.h.b : com.perimeterx.mobile_sdk.doctor_app.ui.h.a);
        arrayList.add("");
        return arrayList;
    }
}
