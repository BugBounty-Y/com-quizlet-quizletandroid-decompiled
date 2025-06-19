package com.quizlet.features.questiontypes.written.ui;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.assembly.compose.input.u;
import com.quizlet.assembly.compose.input.w;

/* loaded from: classes3.dex */
public final class j implements o {
    public static final j a = new j();

    @Override // com.quizlet.features.questiontypes.written.ui.o
    public final w a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-81504867);
        c0814p.X(-1037521253);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarP = com.quizlet.ui.resources.icons.d.p(c0814p);
        c0814p.p(false);
        u uVar = new u(bVarP);
        c0814p.p(false);
        return uVar;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof j);
    }

    public final int hashCode() {
        return -57699554;
    }

    public final String toString() {
        return "CorrectCheck";
    }
}
