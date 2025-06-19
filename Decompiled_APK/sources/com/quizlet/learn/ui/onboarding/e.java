package com.quizlet.learn.ui.onboarding;

import androidx.compose.foundation.layout.D;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X4;
import com.quizlet.learn.data.onboarding.o;
import com.quizlet.learn.data.onboarding.r;
import com.quizlet.learn.data.onboarding.s;
import com.quizlet.learn.data.onboarding.u;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.w;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class e {
    public static final kotlinx.collections.immutable.e a = AbstractC3409x1.h(o.d, s.d, r.d);

    public static final void a(u defaultKnowledge, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        InterfaceC0773a0 interfaceC0773a0;
        Intrinsics.checkNotNullParameter(D.a, "<this>");
        Intrinsics.checkNotNullParameter(defaultKnowledge, "defaultKnowledge");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(722422536);
        int i2 = (c0814p.f(defaultKnowledge) ? 32 : 16) | i | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 145) == 144 && c0814p.x()) {
            c0814p.Q();
        } else {
            V v = C0804k.a;
            c0814p.X(1008195642);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z(defaultKnowledge);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            V v2 = v;
            Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_onboarding_knowledge_header), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(w.b)).i, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            for (u uVar : a) {
                q qVarC = K0.c(n.b, 1.0f);
                String strD = AbstractC3106b5.d(c0814p, uVar.b);
                boolean zB = Intrinsics.b((u) interfaceC0773a02.getValue(), uVar);
                c0814p.X(97780847);
                boolean zF = c0814p.f(uVar) | ((i2 & 896) == 256);
                Object objI2 = c0814p.I();
                V v3 = v2;
                if (zF || objI2 == v3) {
                    interfaceC0773a0 = interfaceC0773a02;
                    objI2 = new androidx.work.impl.utils.q(uVar, function1, interfaceC0773a0, 26);
                    c0814p.i0(objI2);
                } else {
                    interfaceC0773a0 = interfaceC0773a02;
                }
                c0814p.p(false);
                X4.a(strD, zB, qVarC, null, false, (Function0) objI2, c0814p, 384, 24);
                v2 = v3;
                interfaceC0773a02 = interfaceC0773a0;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(defaultKnowledge, function1, i, 14);
        }
    }
}
