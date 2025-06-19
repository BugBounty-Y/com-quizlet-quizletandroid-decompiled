package com.quizlet.explanations.questiondetail.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class c implements d, com.quizlet.assembly.compose.menu.options.a {
    public static final c a = new c();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, 1450905758, R.string.share, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-2095874932);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarK = com.quizlet.ui.resources.icons.d.K(c0814p);
        c0814p.p(false);
        return bVarK;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof c);
    }

    public final int hashCode() {
        return 1779991384;
    }

    public final String toString() {
        return "Share";
    }
}
