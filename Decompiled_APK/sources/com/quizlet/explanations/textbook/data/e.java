package com.quizlet.explanations.textbook.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O5;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class e implements d, com.quizlet.assembly.compose.menu.options.a {
    public static final e a = new e();

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, 219292319, R.string.report_content, c0814p, false);
    }

    @Override // com.quizlet.assembly.compose.menu.options.a
    public final androidx.compose.ui.graphics.painter.b b(InterfaceC0806l interfaceC0806l) {
        return O5.a(interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof e);
    }

    public final int hashCode() {
        return -417440019;
    }

    public final String toString() {
        return "Report";
    }
}
