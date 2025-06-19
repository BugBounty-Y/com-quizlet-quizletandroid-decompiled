package com.quizlet.features.notes.detail.menu;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class b implements f {
    public static final b a = new b();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, -1593211503, R.string.magic_notes_detail_edit_title, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1122243071);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarV = com.quizlet.ui.resources.icons.d.v(c0814p);
        c0814p.p(false);
        return bVarV;
    }

    @Override // com.quizlet.features.notes.detail.menu.f
    public final boolean c() {
        return false;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof b);
    }

    public final int hashCode() {
        return -1108546256;
    }

    public final String toString() {
        return "EditTitle";
    }
}
