package com.quizlet.assembly.compose.buttons;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U4;

/* renamed from: com.quizlet.assembly.compose.buttons.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4093s implements InterfaceC4099y {
    public static final C4093s a = new C4093s();

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final androidx.compose.ui.text.L b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(636028922);
        androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
        c0814p.p(false);
        return l;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4099y
    public final A0 c(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1640576647);
        float f = 12;
        com.quizlet.themes.m.g.q();
        float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
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
        return U4.b(interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof C4093s);
    }

    public final int hashCode() {
        return 1759246626;
    }

    public final String toString() {
        return "Large";
    }
}
