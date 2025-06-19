package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class c implements g {
    public static final c a = new c();

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, -78130307, R.string.create_new_folder, c0814p, false);
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String c(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-924817719);
        c0814p.p(false);
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final androidx.compose.ui.graphics.painter.b d(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(952592887);
        ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarF = com.quizlet.ui.resources.icons.d.F(c0814p);
        c0814p.p(false);
        return bVarF;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof c);
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final long getId() {
        return -1L;
    }

    public final int hashCode() {
        return -1666871152;
    }

    public final String toString() {
        return "NewFolder";
    }
}
