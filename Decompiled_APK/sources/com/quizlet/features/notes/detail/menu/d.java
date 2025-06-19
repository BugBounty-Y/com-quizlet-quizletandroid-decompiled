package com.quizlet.features.notes.detail.menu;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O5;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class d implements f, com.quizlet.assembly.compose.menu.options.a {
    public static final d a = new d();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, -772122822, R.string.magic_notes_detail_report_content, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        return O5.a(interfaceC0806l);
    }

    @Override // com.quizlet.features.notes.detail.menu.f
    public final boolean c() {
        return false;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof d);
    }

    public final int hashCode() {
        return 603043431;
    }

    public final String toString() {
        return "ReportContent";
    }
}
