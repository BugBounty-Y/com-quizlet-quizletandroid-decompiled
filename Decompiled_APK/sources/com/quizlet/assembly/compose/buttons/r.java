package com.quizlet.assembly.compose.buttons;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U4;

/* loaded from: classes2.dex */
public final class r implements InterfaceC4099y {
    public static final r a = new r();

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final androidx.compose.ui.text.L b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(963458680);
        androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
        c0814p.p(false);
        return l;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final A0 c(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(929192133);
        com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
        mVar.o();
        float f = com.quizlet.ui.resources.designsystem.generated.j.p;
        mVar.p();
        float f2 = com.quizlet.ui.resources.designsystem.generated.j.j;
        A0 a0 = new A0(f2, f, f2, f);
        c0814p.p(false);
        return a0;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final float d(InterfaceC0806l interfaceC0806l, int i) {
        U4.a(interfaceC0806l);
        return com.quizlet.ui.resources.designsystem.generated.h.f;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final androidx.compose.foundation.shape.d e(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(458055059);
        com.quizlet.themes.m.g.b();
        androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j);
        c0814p.p(false);
        return dVarA;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof r);
    }

    public final int hashCode() {
        return -1402615900;
    }

    public final String toString() {
        return "ExtraRoundLarge";
    }
}
