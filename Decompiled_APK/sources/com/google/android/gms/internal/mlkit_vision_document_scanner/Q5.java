package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;

/* loaded from: classes2.dex */
public abstract class Q5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(530839280);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.j();
            androidx.compose.ui.q qVarL = androidx.compose.foundation.layout.K0.l(qVar, com.quizlet.ui.resources.designsystem.generated.h.i, com.quizlet.themes.m.o);
            long jS = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).s();
            mVar.b();
            float f = com.quizlet.ui.resources.designsystem.generated.f.j;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarL, jS, androidx.compose.foundation.shape.e.a(f));
            mVar.b();
            AbstractC0409s.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.draw.g.c(qVarF, androidx.compose.foundation.shape.e.a(f)), "assemblyDragHandle"), c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 2, qVar);
        }
    }
}
