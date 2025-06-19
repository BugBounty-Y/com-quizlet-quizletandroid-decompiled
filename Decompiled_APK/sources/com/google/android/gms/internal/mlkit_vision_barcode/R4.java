package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class R4 {
    public static final androidx.compose.ui.geometry.c a(long j, long j2) {
        return new androidx.compose.ui.geometry.c(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.e.d(j2) + androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.e.b(j2) + androidx.compose.ui.geometry.b.e(j));
    }

    public static final void b(com.quizlet.assembly.compose.modals.x modalState, androidx.compose.ui.n nVar, String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2009618727);
        int i2 = (c0814p.h(modalState) ? 4 : 2) | i | 48 | (c0814p.f(str) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(modalState, nVar3, false, null, null, null, androidx.compose.runtime.internal.e.e(-214586078, new com.quizlet.assembly.compose.menu.l(str, function0, modalState, 9), c0814p), c0814p, (i2 & 14) | 1572920, 60);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(modalState, nVar2, str, function0, i);
        }
    }

    public abstract String c();
}
