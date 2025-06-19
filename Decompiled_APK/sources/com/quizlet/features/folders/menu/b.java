package com.quizlet.features.folders.menu;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class b implements c {
    public static final b a = new b();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, 1033822514, R.string.study_guide, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-545690208);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarC = com.quizlet.ui.resources.icons.d.C(c0814p);
        c0814p.p(false);
        return bVarC;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof b);
    }

    public final int hashCode() {
        return 1423853114;
    }

    public final String toString() {
        return "MagicNotes";
    }
}
