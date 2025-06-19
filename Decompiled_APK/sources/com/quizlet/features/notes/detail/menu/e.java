package com.quizlet.features.notes.detail.menu;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class e implements f {
    public static final e a = new e();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, -1466519842, R.string.magic_notes_detail_original_upload, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1654112720);
        com.quizlet.themes.e.a(c0814p).a.getClass();
        c0814p.X(901806670);
        return Z.d(R.drawable.ic_sys_explanations, c0814p, 0, false, false);
    }

    @Override // com.quizlet.features.notes.detail.menu.f
    public final boolean c() {
        return false;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof e);
    }

    public final int hashCode() {
        return -1493881675;
    }

    public final String toString() {
        return "ViewOriginalUpload";
    }
}
