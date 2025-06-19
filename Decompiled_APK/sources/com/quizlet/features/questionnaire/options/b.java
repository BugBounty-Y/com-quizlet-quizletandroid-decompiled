package com.quizlet.features.questionnaire.options;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.quizlet.features.folders.composables.Z;
import com.quizlet.features.practicetest.detail.composables.e;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.j;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    /* JADX WARN: Removed duplicated region for block: B:45:0x0110  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.questionnaire.navigation.Control.Button r26, androidx.compose.ui.q r27, androidx.compose.runtime.InterfaceC0806l r28, int r29) {
        /*
            Method dump skipped, instructions count: 440
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questionnaire.options.b.a(com.quizlet.features.questionnaire.navigation.Control$Button, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void b(kotlinx.collections.immutable.b options, q qVar, Function1 onOptionSelected, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(onOptionSelected, "onOptionSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1692641745);
        int i2 = i | (c0814p.f(options) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(onOptionSelected) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            m.g.s();
            C0392j c0392jG = AbstractC0398m.g(j.h);
            c0814p.X(1705785099);
            boolean z = ((i2 & 14) == 4) | ((i2 & 896) == 256);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new Z(options, onOptionSelected);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVar, null, null, c0392jG, null, null, false, (Function1) objI, c0814p, (i2 >> 3) & 14, 238);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new e(options, qVar, onOptionSelected, i, 1);
        }
    }
}
