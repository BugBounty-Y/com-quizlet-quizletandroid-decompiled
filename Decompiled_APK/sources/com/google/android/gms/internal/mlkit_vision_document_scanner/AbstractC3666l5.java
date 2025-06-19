package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.achievements.ui.composables.C4214a;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.l5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3666l5 {
    public static final void a(com.quizlet.ui.models.content.carditem.c folderData, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(folderData, "folderData");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1488707287);
        int i2 = i | (c0814p2.h(folderData) ? 4 : 2) | 432 | (c0814p2.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            c0814p2.X(385331960);
            boolean zH = ((i2 & 7168) == 2048) | c0814p2.h(folderData);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.braze.triggers.managers.h(15, function1, folderData);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            R4.a(qVarC, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-1301365277, new com.quizlet.assembly.compose.cards.c(folderData, 2), c0814p2), c0814p, 0, 990);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 3, folderData, nVar2, function1);
        }
    }

    public static final void b(String text, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-517808153);
        int i2 = i | (c0814p2.f(text) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(text, qVar, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).l, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(text, qVar, i, 8);
        }
    }
}
