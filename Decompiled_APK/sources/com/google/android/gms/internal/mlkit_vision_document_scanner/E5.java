package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.I;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E5 {
    public static final void a(com.quizlet.quizletandroid.ui.onboarding.h viewModel, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1165998091);
        if ((i & 17) == 16 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0409s.a(qVar, c0814p, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(viewModel, qVar, i, 21);
        }
    }

    public static final void b(final float f, final androidx.compose.ui.q qVar, androidx.compose.ui.graphics.I i, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        int i4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1789951360);
        if ((i2 & 6) == 0) {
            i4 = (c0814p.c(f) ? 4 : 2) | i2;
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= ((i3 & 4) == 0 && c0814p.f(i)) ? 256 : 128;
        }
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i2 & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            } else if ((i3 & 4) != 0) {
                c0814p.X(-114951376);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                i = c(AbstractC3409x1.h(new C0861v(((com.quizlet.themes.b) c0814p.j(b)).b.h()), new C0861v(((com.quizlet.themes.b) c0814p.j(b)).S), new C0861v(((com.quizlet.themes.b) c0814p.j(b)).b.h())), c0814p);
                c0814p.p(false);
            }
            c0814p.q();
            com.quizlet.themes.m.g.e();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(AbstractC0460p.e(qVar, i, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.f), 4), f));
        }
        final androidx.compose.ui.graphics.I i5 = i;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.loading.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    I i6 = i5;
                    E5.b(f, qVar, i6, (InterfaceC0806l) obj, iH, i3);
                    return Unit.a;
                }
            };
        }
    }

    public static final androidx.compose.ui.graphics.I c(kotlinx.collections.immutable.e colors, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(colors, "colors");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(2944441);
        androidx.compose.animation.core.J jG = AbstractC0240f.g(AbstractC0240f.p("", c0814p, 0), DefinitionKt.NO_Float_VALUE, 1500.0f, AbstractC0240f.o(AbstractC0240f.r(1500, 0, null, 6), 4), "", c0814p, 29112, 0);
        androidx.compose.ui.graphics.I i = new androidx.compose.ui.graphics.I(colors, null, 0L, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(((Number) ((androidx.compose.runtime.L0) jG.d).getValue()).floatValue(), ((Number) ((androidx.compose.runtime.L0) jG.d).getValue()).floatValue()));
        c0814p.p(false);
        return i;
    }
}
