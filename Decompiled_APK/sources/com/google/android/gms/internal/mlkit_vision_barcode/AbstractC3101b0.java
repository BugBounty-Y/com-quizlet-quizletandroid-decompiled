package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3101b0 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1750933758);
        if ((((c0814p2.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.report_ai_enhancement), androidx.compose.foundation.layout.K0.c(qVar, 1.0f), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).q, c0814p, 0, 0, 65016);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 23, qVar);
        }
    }

    public static final int b(androidx.compose.foundation.lazy.grid.r rVar, EnumC0320d0 enumC0320d0) {
        return (int) (enumC0320d0 == EnumC0320d0.a ? rVar.t & 4294967295L : rVar.t >> 32);
    }
}
