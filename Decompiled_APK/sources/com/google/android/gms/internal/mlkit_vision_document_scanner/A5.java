package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final androidx.compose.runtime.internal.d text, final androidx.compose.ui.q qVar, final androidx.compose.runtime.internal.d dVar, final androidx.compose.runtime.internal.d dVar2, final float f, final androidx.compose.foundation.layout.A0 a0, float f2, final Function0 function0, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        float f3;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1565522989);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.c(f) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.f(a0) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            f3 = f2;
            i2 |= c0814p.c(f3) ? 1048576 : 524288;
        } else {
            f3 = f2;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(function0) ? 8388608 : 4194304;
        }
        if ((4793491 & i2) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarL = AbstractC0460p.l(androidx.compose.ui.draw.g.c(qVar, androidx.compose.foundation.shape.e.a(f3)), false, null, function0, 7);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            int i4 = i2;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.ui.n.b, a0);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(f), androidx.compose.ui.b.k, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarT);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            c0814p.X(-587615644);
            if (dVar != null) {
                dVar.invoke(c0814p, Integer.valueOf((i4 >> 6) & 14));
            }
            c0814p.p(false);
            text.invoke(c0814p, Integer.valueOf(i4 & 14));
            c0814p.X(-587612284);
            if (dVar2 != null) {
                dVar2.invoke(c0814p, Integer.valueOf((i4 >> 9) & 14));
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final float f4 = f3;
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.links.k
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    androidx.compose.runtime.internal.d dVar3 = text;
                    float f5 = f4;
                    Function0 function02 = function0;
                    A5.a(dVar3, qVar, dVar, dVar2, f, a0, f5, function02, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
