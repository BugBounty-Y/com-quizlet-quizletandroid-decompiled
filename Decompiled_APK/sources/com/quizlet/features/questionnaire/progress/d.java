package com.quizlet.features.questionnaire.progress;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.K0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.e;
import androidx.compose.ui.n;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import com.quizlet.features.questionnaire.navigation.Progress;
import com.quizlet.themes.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class d {
    public static final K0 a = AbstractC0240f.r(0, 0, com.quizlet.themes.a.c.c(), 3);

    /* JADX WARN: Removed duplicated region for block: B:37:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:54:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final long r12, final float r14, final androidx.compose.ui.q r15, kotlin.jvm.functions.c r16, androidx.compose.runtime.InterfaceC0806l r17, final int r18, final int r19) {
        /*
            Method dump skipped, instructions count: 254
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questionnaire.progress.d.a(long, float, androidx.compose.ui.q, kotlin.jvm.functions.c, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(Progress progress, q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(progress, "progress");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1521813792);
        int i4 = (c0814p.f(progress) ? 4 : 2) | i;
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
        } else {
            i3 = i4 | (c0814p.f(qVar) ? 32 : 16);
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i5 != 0) {
                qVar = n.b;
            }
            a(((com.quizlet.themes.b) c0814p.j(g.a)).t, 1.0f, N.G(qVar, "EMPTY_PROGRESS_BAR_TAG"), e.e(1882185839, new com.quizlet.baseui.base.d(progress, 8), c0814p), c0814p, 3120, 0);
        }
        q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(progress, qVar2, i, i2, 16);
        }
    }
}
