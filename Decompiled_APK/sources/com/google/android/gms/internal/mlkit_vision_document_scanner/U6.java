package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public abstract class U6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g gVar, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1724707360);
        int i2 = i | (c0814p2.h(gVar) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            boolean z = false;
            if (gVar != null && gVar.b.a) {
                z = true;
            }
            c0814p = c0814p2;
            R4.a(qVar, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(835271130, new com.quizlet.assembly.compose.listitems.v(gVar, z, function1, 4), c0814p2), c0814p, (i2 >> 3) & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 6, gVar, qVar, function1);
        }
    }
}
