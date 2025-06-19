package com.quizlet.ui.compose;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.ui.compose.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4810c {
    public static final float a = 240;
    public static final float b = (float) 4.0d;
    public static final float c;
    public static final androidx.compose.ui.q d;

    static {
        float f = 10;
        c = f;
        d = AbstractC0382e.w(androidx.compose.ui.semantics.m.a(AbstractC0897s.j(androidx.compose.ui.n.b, new com.perimeterx.mobile_sdk.api_data.h(1)), true, new com.quizlet.qutils.android.f(20)), DefinitionKt.NO_Float_VALUE, f, 1);
    }

    public static final void a(final Function0 primaryProgress, final Function0 secondaryProgress, final androidx.compose.ui.q qVar, final long j, final long j2, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        Intrinsics.checkNotNullParameter(primaryProgress, "primaryProgress");
        Intrinsics.checkNotNullParameter(secondaryProgress, "secondaryProgress");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(72179776);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(primaryProgress) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(secondaryProgress) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.e(j2) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            c0814p.X(304525947);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (z || objI == obj) {
                objI = new com.quizlet.features.setpage.composable.a(22, primaryProgress);
                c0814p.i0(objI);
            }
            final Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(304528317);
            boolean z2 = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == obj) {
                objI2 = new com.quizlet.features.setpage.composable.a(23, secondaryProgress);
                c0814p.i0(objI2);
            }
            final Function0 function02 = (Function0) objI2;
            c0814p.p(false);
            androidx.compose.ui.q qVarG = qVar.g(d);
            c0814p.X(304533540);
            boolean zF = c0814p.f(function02);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.assembly.compose.input.d(15, function02);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = K0.l(androidx.compose.ui.semantics.m.a(qVarG, true, (Function1) objI3), a, b);
            c0814p.X(304539699);
            boolean zF2 = c0814p.f(function0) | c0814p.f(function02) | ((((57344 & i2) ^ 24576) > 16384 && c0814p.e(j2)) || (i2 & 24576) == 16384) | ((((i2 & 7168) ^ 3072) > 2048 && c0814p.e(j)) || (i2 & 3072) == 2048);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == obj) {
                objI4 = new Function1() { // from class: com.quizlet.ui.compose.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj2) {
                        androidx.compose.ui.graphics.drawscope.d Canvas = (androidx.compose.ui.graphics.drawscope.d) obj2;
                        Intrinsics.checkNotNullParameter(Canvas, "$this$Canvas");
                        float fFloatValue = ((Number) function0.invoke()).floatValue();
                        float fFloatValue2 = ((Number) function02.invoke()).floatValue();
                        com.quizlet.themes.m.g.b();
                        float f = com.quizlet.ui.resources.designsystem.generated.f.j;
                        long jA = O4.a(f, f);
                        AbstractC4810c.b(Canvas, fFloatValue2, j2, jA);
                        AbstractC4810c.b(Canvas, fFloatValue, j, jA);
                        return Unit.a;
                    }
                };
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            AbstractC0460p.b(qVarL, (Function1) objI4, c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.ui.compose.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj2, Object obj3) {
                    ((Integer) obj3).getClass();
                    int iH = C0776c.H(i | 1);
                    long j3 = j;
                    long j4 = j2;
                    AbstractC4810c.a(primaryProgress, secondaryProgress, qVar, j3, j4, (InterfaceC0806l) obj2, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(androidx.compose.ui.graphics.drawscope.d dVar, float f, long j, long j2) {
        float fD = androidx.compose.ui.geometry.e.d(dVar.g());
        float fB = androidx.compose.ui.geometry.e.b(dVar.g());
        androidx.compose.ui.graphics.drawscope.d.z0(dVar, j, Q4.c((dVar.getLayoutDirection() == androidx.compose.ui.unit.k.a ? 0.0f : 1.0f - f) * fD, DefinitionKt.NO_Float_VALUE), T4.a(fD * f, fB), j2, null, 240);
    }
}
