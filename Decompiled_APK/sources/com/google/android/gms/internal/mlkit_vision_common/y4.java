package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_common.y4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class y4 {
    public static final void a(final String setTitle, final androidx.compose.ui.text.L titleStyle, final androidx.compose.ui.text.L headerStyle, float f, float f2, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        final androidx.compose.ui.n nVar2;
        float f3 = f;
        float f4 = f2;
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(titleStyle, "titleStyle");
        Intrinsics.checkNotNullParameter(headerStyle, "headerStyle");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1753670728);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(setTitle) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(titleStyle) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(headerStyle) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.c(f3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.c(f4) ? 16384 : 8192;
        }
        int i3 = i2 | 196608;
        if ((i3 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(setTitle, qVarY, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, titleStyle, c0814p, i3 & 14, (i3 << 15) & 3670016, 65528);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_onboarding_header), null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, headerStyle, c0814p, 0, (i3 << 12) & 3670016, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            f4 = f2;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar3, f4));
            f3 = f;
            AbstractC0460p.c(((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).b.f(c0814p), null, androidx.compose.foundation.layout.K0.k(nVar3, f3), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final float f5 = f4;
            final float f6 = f3;
            c0813o0R.d = new Function2() { // from class: com.quizlet.learn.ui.onboarding.d
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    float f7 = f5;
                    n nVar4 = nVar2;
                    y4.a(setTitle, titleStyle, headerStyle, f6, f7, nVar4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static void b(Object obj, String str) {
        if (obj == null) {
            throw new NullPointerException(str);
        }
    }
}
