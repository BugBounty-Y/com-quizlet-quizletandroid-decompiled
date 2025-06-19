package com.quizlet.assembly.compose.buttons;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U4;

/* renamed from: com.quizlet.assembly.compose.buttons.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4095u implements InterfaceC4099y {
    public static final C4095u a = new C4095u();

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final androidx.compose.ui.text.L b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1431245538);
        androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k;
        c0814p.p(false);
        return l;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final A0 c(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(875950837);
        com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
        mVar.r();
        float f = com.quizlet.ui.resources.designsystem.generated.j.e;
        mVar.r();
        A0 a0 = new A0(f, f, f, f);
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
        c0814p.X(999300199);
        com.quizlet.themes.m.g.b();
        androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j);
        c0814p.p(false);
        return dVarA;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof C4095u);
    }

    public final int hashCode() {
        return -1954444848;
    }

    public final String toString() {
        return "NoPaddingSmall";
    }
}
