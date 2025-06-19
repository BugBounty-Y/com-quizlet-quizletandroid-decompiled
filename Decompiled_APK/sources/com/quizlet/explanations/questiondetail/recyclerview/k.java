package com.quizlet.explanations.questiondetail.recyclerview;

import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.r3;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.X;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public abstract class k {
    static {
        new e("How do I calculate the volume of a sphere?", m.a, null, false, true, new X(1, 2), new com.quizlet.db.data.models.persisted.types.a(18), new Z(25));
    }

    public static final void a(SimpleImage simpleImage, Function0 function0, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-362645183);
        if ((((c0814p.h(simpleImage) ? 4 : 2) | i | (c0814p.f(qVar) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1573400532);
            c0814p.X(-1573399922);
            if (simpleImage.d) {
                androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
                Integer num = simpleImage.c;
                if (num == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                K0.o(qVar, bVar.O(num.intValue()));
                Integer num2 = simpleImage.b;
                if (num2 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                K0.d(qVar, bVar.O(num2.intValue()));
            }
            c0814p.p(false);
            Unit unit = Unit.a;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1573391599, c0814p, false);
            if (objG == C0804k.a) {
                objG = new com.quizlet.assembly.compose.input.d(6, function0);
                c0814p.i0(objG);
            }
            c0814p.p(false);
            r3.a(simpleImage.a, null, qVar, (Function1) objG, null, null, c0814p, 48, 2024);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(simpleImage, function0, qVar, i, 9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:113:0x045b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x02ba  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0308  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x030e  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x032c  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0347  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0355  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0380  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.explanations.questiondetail.recyclerview.g r48, androidx.compose.ui.n r49, androidx.compose.runtime.InterfaceC0806l r50, int r51) {
        /*
            Method dump skipped, instructions count: 1147
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.questiondetail.recyclerview.k.b(com.quizlet.explanations.questiondetail.recyclerview.g, androidx.compose.ui.n, androidx.compose.runtime.l, int):void");
    }
}
