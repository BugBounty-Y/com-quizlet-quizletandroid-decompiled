package com.quizlet.features.folders.menu;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class a implements c {
    public static final a a = new a();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, 1536521027, R.string.flashcard_set, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1934714901);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarI = com.quizlet.ui.resources.icons.d.I(c0814p);
        c0814p.p(false);
        return bVarI;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof a);
    }

    public final int hashCode() {
        return -1784768759;
    }

    public final String toString() {
        return "FlashcardsSet";
    }
}
