package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.appcompat.app.L;
import androidx.compose.animation.d0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.drawscope.d;
import androidx.compose.ui.graphics.drawscope.h;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3729t5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.t5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3729t5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final float f, androidx.compose.ui.q qVar, final float f2, final float f3, final long j, final long j2, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        final float f4;
        androidx.compose.ui.q qVar2;
        final androidx.compose.ui.q qVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1026499999);
        if ((i & 6) == 0) {
            i2 = (c0814p.c(f) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            f4 = f2;
            i3 |= c0814p.c(f4) ? 256 : 128;
        } else {
            f4 = f2;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.c(f3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.e(j) ? 16384 : 8192;
        }
        if ((i & 196608) == 0) {
            i3 |= c0814p.e(j2) ? 131072 : 65536;
        }
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                qVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                qVar2 = qVar;
            }
            c0814p.q();
            final float f5 = f3 / 10;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVar2, f3), "ArcProgressBar");
            c0814p.X(-1668558163);
            boolean zC = c0814p.c(f5) | ((i3 & 7168) == 2048) | ((((57344 & i3) ^ 24576) > 16384 && c0814p.e(j)) || (i3 & 24576) == 16384) | ((i3 & 896) == 256) | ((((458752 & i3) ^ 196608) > 131072 && c0814p.e(j2)) || (i3 & 196608) == 131072) | ((i3 & 14) == 4);
            Object objI = c0814p.I();
            if (zC || objI == C0804k.a) {
                Function1 function1 = new Function1() { // from class: com.quizlet.assembly.compose.components.progress.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) throws Throwable {
                        long j3;
                        float f6 = f4;
                        long j4 = j2;
                        float f7 = f;
                        d Canvas = (d) obj;
                        Intrinsics.checkNotNullParameter(Canvas, "$this$Canvas");
                        float fC0 = Canvas.c0(f5);
                        float fC02 = Canvas.c0(f3) - fC0;
                        float f8 = fC0 / 2;
                        Canvas.f0(j, DefinitionKt.NO_Float_VALUE, 360.0f, Q4.c(f8, f8), T4.a(fC02, fC02), (768 & 64) != 0 ? 1.0f : DefinitionKt.NO_Float_VALUE, new h(fC0, DefinitionKt.NO_Float_VALUE, 0, 0, 30));
                        com.quizlet.data.repository.folderset.c cVarE0 = Canvas.e0();
                        long jR = cVarE0.r();
                        cVarE0.o().e();
                        try {
                            L l = (L) cVarE0.b;
                            l.O(T4.c(((com.quizlet.data.repository.folderset.c) l.b).r()), f6);
                            try {
                                Canvas.f0(j4, DefinitionKt.NO_Float_VALUE, 360 * f7, Q4.c(f8, f8), T4.a(fC02, fC02), (768 & 64) != 0 ? 1.0f : DefinitionKt.NO_Float_VALUE, new h(fC0, DefinitionKt.NO_Float_VALUE, 1, 0, 26));
                                d0.y(cVarE0, jR);
                                return Unit.a;
                            } catch (Throwable th) {
                                th = th;
                                j3 = jR;
                                d0.y(cVarE0, j3);
                                throw th;
                            }
                        } catch (Throwable th2) {
                            th = th2;
                            j3 = jR;
                        }
                    }
                };
                c0814p.i0(function1);
                objI = function1;
            }
            c0814p.p(false);
            AbstractC0460p.b(qVarG, (Function1) objI, c0814p, 0);
            qVar3 = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.components.progress.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    long j3 = j;
                    long j4 = j2;
                    AbstractC3729t5.a(f, qVar3, f2, f3, j3, j4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
