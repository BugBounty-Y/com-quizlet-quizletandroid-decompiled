package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class L3 {
    public static final void a(com.quizlet.features.infra.models.a termContentTextData, long j, androidx.compose.ui.q qVar, boolean z, String str, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        kotlin.jvm.functions.c cVar2;
        boolean z2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(termContentTextData, "termContentTextData");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-288992199);
        if ((i & 6) == 0) {
            i2 = i | (c0814p2.f(termContentTextData) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.e(j) ? 32 : 16;
        }
        int i3 = i2 | (c0814p2.f(qVar) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.f(str) ? 16384 : 8192);
        if ((i & 196608) == 0) {
            cVar2 = cVar;
            i3 |= c0814p2.h(cVar2) ? 131072 : 65536;
        } else {
            cVar2 = cVar;
        }
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "term_section_rich_text");
            c0814p2.X(-1511681356);
            boolean z3 = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((458752 & i3) == 131072) | ((i3 & 7168) == 2048) | ((i3 & 57344) == 16384);
            Object objI = c0814p2.I();
            if (z3 || objI == v) {
                z2 = false;
                com.quizlet.features.termlist.ui.composables.a aVar = new com.quizlet.features.termlist.ui.composables.a(cVar2, j, z, str, 1);
                c0814p2.i0(aVar);
                objI = aVar;
            } else {
                z2 = false;
            }
            c0814p2.p(z2);
            c0814p = c0814p2;
            AbstractC3164i0.c(termContentTextData.c, termContentTextData.a, termContentTextData.d, termContentTextData.b, AbstractC0460p.l(qVarG, z2, null, (Function0) objI, 7), ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0, 0, null, null, c0814p, 0, 0, 1920);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.termlist.ui.composables.f(termContentTextData, j, qVar, z, str, cVar, i);
        }
    }

    public static int b(Object obj) {
        return (int) (Integer.rotateLeft((int) ((obj == null ? 0 : obj.hashCode()) * (-862048943)), 15) * 461845907);
    }
}
