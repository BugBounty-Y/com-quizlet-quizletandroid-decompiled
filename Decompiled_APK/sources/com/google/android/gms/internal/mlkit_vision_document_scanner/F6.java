package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class F6 {
    public static final void c(com.quizlet.assembly.compose.modals.x modalState, Function0 onRestartClick, Function0 onDismissClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(onRestartClick, "onRestartClick");
        Intrinsics.checkNotNullParameter(onDismissClick, "onDismissClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2073169551);
        int i2 = i | (c0814p.h(modalState) ? 4 : 2) | (c0814p.h(onRestartClick) ? 32 : 16) | (c0814p.h(onDismissClick) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            U5.b(modalState, androidx.compose.ui.platform.N.G(nVar, "restart_learn_modal"), false, null, null, onDismissClick, androidx.compose.runtime.internal.e.e(-921356406, new com.quizlet.features.notes.upload.composables.upload.b(4, onRestartClick, onDismissClick), c0814p), c0814p, (i2 & 14) | 1572872 | ((i2 << 9) & 458752), 28);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a((Object) modalState, onRestartClick, onDismissClick, qVar2, i, 4);
        }
    }
}
