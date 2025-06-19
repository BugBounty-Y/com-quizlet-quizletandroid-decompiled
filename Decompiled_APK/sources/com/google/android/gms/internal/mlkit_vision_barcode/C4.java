package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0790d;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, com.quizlet.assembly.compose.modals.x modalState, Function0 function0) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-275150894);
        int i2 = (c0814p.h(modalState) ? 4 : 2) | i | 48 | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(modalState, nVar3, false, null, null, null, androidx.compose.runtime.internal.e.e(174964087, new androidx.navigation.compose.o(17, function0, modalState), c0814p), c0814p, (i2 & 14) | 1572920, 60);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 19, modalState, nVar2, function0);
        }
    }

    public static final void b(androidx.compose.runtime.D0 d0, InterfaceC0790d interfaceC0790d, int i) {
        while (true) {
            int i2 = d0.v;
            if (i > i2 && i < d0.u) {
                return;
            }
            if (i2 == 0 && i == 0) {
                return;
            }
            d0.L();
            if (d0.w(d0.v)) {
                interfaceC0790d.h();
            }
            d0.i();
        }
    }
}
