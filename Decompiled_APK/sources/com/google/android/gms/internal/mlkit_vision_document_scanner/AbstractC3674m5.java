package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.m5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3674m5 {
    public static final void a(com.quizlet.ui.models.content.carditem.d data, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-19755516);
        int i2 = i | (c0814p2.h(data) ? 4 : 2) | 432 | (c0814p2.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(653390481);
            boolean zH = ((i2 & 7168) == 2048) | c0814p2.h(data);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.braze.triggers.managers.h(16, function1, data);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            R4.a(nVar3, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(1123662730, new com.quizlet.assembly.compose.cards.c(data, 3), c0814p2), c0814p, 6, 990);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 4, data, nVar2, function1);
        }
    }
}
