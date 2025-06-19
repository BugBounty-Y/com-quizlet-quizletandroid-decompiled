package com.quizlet.learn.ui.progress;

import android.content.res.Resources;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.K0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.airbnb.lottie.compose.o;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import com.google.android.gms.internal.mlkit_vision_common.r;
import com.quizlet.assembly.compose.modals.t;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.m;
import com.quizlet.ui.compose.AbstractC4810c;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class e {
    public static final K0 a;
    public static final K0 b;

    static {
        com.quizlet.themes.a aVar = com.quizlet.themes.a.c;
        a = AbstractC0240f.r(0, 0, aVar.c(), 3);
        b = AbstractC0240f.r(0, 0, aVar.a(), 3);
    }

    public static final void a(int i, n nVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-940779140);
        if ((((c0814p.d(i) ? 4 : 2) | i2 | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            n nVar2 = n.b;
            nVar = nVar2;
            AbstractC3515q.a((com.airbnb.lottie.h) r.d(new o(R.raw.summary_screen_confetti), c0814p).getValue(), AbstractC0382e.y(nVar2, i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 0, androidx.compose.ui.b.d, C0888i.f, c0814p, 0, 1769472, 4095996);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new c(i, nVar, i2, 0);
        }
    }

    public static final void b(final int i, final int i2, final int i3, f fVar, final q qVar, long j, long j2, long j3, androidx.compose.foundation.shape.d dVar, final Function0 onAnimationFinish, InterfaceC0806l interfaceC0806l, final int i4) {
        int i5;
        long jL;
        int i6;
        androidx.compose.foundation.shape.d dVarA;
        long j4;
        final long j5;
        float f;
        InterfaceC0773a0 interfaceC0773a0;
        C0814p c0814p;
        long j6;
        F0 f0;
        W0 w0;
        androidx.compose.foundation.shape.d dVar2;
        W0 w02;
        Object[] objArr;
        C0814p c0814p2;
        boolean z;
        final androidx.compose.foundation.shape.d dVar3;
        final long j7;
        final long j8;
        float f2;
        final f progressBarType = fVar;
        Intrinsics.checkNotNullParameter(progressBarType, "progressBarType");
        Intrinsics.checkNotNullParameter(onAnimationFinish, "onAnimationFinish");
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(332616268);
        if ((i4 & 6) == 0) {
            i5 = (c0814p3.d(i) ? 4 : 2) | i4;
        } else {
            i5 = i4;
        }
        if ((i4 & 48) == 0) {
            i5 |= c0814p3.d(i2) ? 32 : 16;
        }
        if ((i4 & 384) == 0) {
            i5 |= c0814p3.d(i3) ? 256 : 128;
        }
        if ((i4 & 3072) == 0) {
            i5 |= c0814p3.f(progressBarType) ? 2048 : 1024;
        }
        if ((i4 & 24576) == 0) {
            i5 |= c0814p3.f(qVar) ? 16384 : 8192;
        }
        if ((196608 & i4) == 0) {
            i5 |= 65536;
        }
        if ((1572864 & i4) == 0) {
            i5 |= 524288;
        }
        if ((12582912 & i4) == 0) {
            i5 |= 4194304;
        }
        if ((100663296 & i4) == 0) {
            i5 |= 33554432;
        }
        if ((805306368 & i4) == 0) {
            i5 |= c0814p3.h(onAnimationFinish) ? 536870912 : 268435456;
        }
        if ((306783379 & i5) == 306783378 && c0814p3.x()) {
            c0814p3.Q();
            j7 = j;
            j8 = j2;
            j5 = j3;
            dVar3 = dVar;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            if ((i4 & 1) == 0 || c0814p3.w()) {
                B b2 = com.quizlet.themes.g.a;
                jL = ((com.quizlet.themes.b) c0814p3.j(b2)).b.l();
                long j9 = ((com.quizlet.themes.b) c0814p3.j(b2)).E0;
                long jB = ((com.quizlet.themes.b) c0814p3.j(b2)).b.b();
                m.g.s();
                i6 = i5 & (-268369921);
                dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.j.h);
                j4 = j9;
                j5 = jB;
            } else {
                c0814p3.Q();
                jL = j;
                j4 = j2;
                j5 = j3;
                i6 = i5 & (-268369921);
                dVarA = dVar;
            }
            c0814p3.q();
            c0814p3.X(-1379713014);
            Object objI = c0814p3.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p3.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            c0814p3.p(false);
            float f3 = i3;
            float f4 = i2 / f3;
            c0814p3.X(-1379708501);
            Object objI2 = c0814p3.I();
            float f5 = DefinitionKt.NO_Float_VALUE;
            if (objI2 == v) {
                int iOrdinal = progressBarType.ordinal();
                if (iOrdinal == 0) {
                    f2 = f4;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    f2 = 0.0f;
                }
                objI2 = C0776c.v(f2);
                c0814p3.i0(objI2);
            }
            F0 f02 = (F0) objI2;
            c0814p3.p(false);
            float fI = f02.i();
            K0 k0 = a;
            W0 w0B = AbstractC0248j.b(fI, k0, "secondaryAnimation", null, c0814p3, 3072, 20);
            float f6 = i / f3;
            c0814p3.X(-1379692279);
            Object objI3 = c0814p3.I();
            if (objI3 == v) {
                int iOrdinal2 = progressBarType.ordinal();
                if (iOrdinal2 == 0) {
                    f5 = f6;
                } else if (iOrdinal2 != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                objI3 = C0776c.v(f5);
                c0814p3.i0(objI3);
            }
            F0 f03 = (F0) objI3;
            c0814p3.p(false);
            float fI2 = f03.i();
            int iOrdinal3 = progressBarType.ordinal();
            if (iOrdinal3 != 0) {
                f = fI2;
                if (iOrdinal3 != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                k0 = b;
            } else {
                f = fI2;
            }
            c0814p3.X(-1379674083);
            int i7 = 1879048192 & i6;
            boolean z2 = i7 == 536870912;
            Object objI4 = c0814p3.I();
            if (z2 || objI4 == v) {
                objI4 = new com.quizlet.features.flashcards.views.composables.f(onAnimationFinish, interfaceC0773a02, 8);
                c0814p3.i0(objI4);
            }
            c0814p3.p(false);
            W0 w0B2 = AbstractC0248j.b(f, k0, "primaryAnimation", (Function1) objI4, c0814p3, 3072, 4);
            Object[] objArr2 = {Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3), onAnimationFinish};
            c0814p3.X(-1379668388);
            boolean z3 = ((i6 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i6 & 7168) == 2048) | ((i6 & 896) == 256) | ((i6 & 14) == 4) | (i7 == 536870912);
            Object objI5 = c0814p3.I();
            if (z3 || objI5 == v) {
                interfaceC0773a0 = interfaceC0773a02;
                c0814p = c0814p3;
                j6 = jL;
                f0 = f03;
                w0 = w0B2;
                dVar2 = dVarA;
                w02 = w0B;
                objArr = objArr2;
                d dVar4 = new d(fVar, i2, i3, i, onAnimationFinish, f02, f0, null);
                c0814p.i0(dVar4);
                objI5 = dVar4;
            } else {
                c0814p = c0814p3;
                interfaceC0773a0 = interfaceC0773a02;
                j6 = jL;
                f0 = f03;
                w0 = w0B2;
                dVar2 = dVarA;
                w02 = w0B;
                objArr = objArr2;
            }
            c0814p.p(false);
            C0776c.h(objArr, (Function2) objI5, c0814p);
            c0814p.X(-1379651186);
            Object objI6 = c0814p.I();
            if (objI6 == v) {
                objI6 = C0776c.z(new androidx.compose.ui.geometry.e(0L));
                c0814p.i0(objI6);
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI6;
            c0814p.p(false);
            m mVar = m.g;
            mVar.s();
            float f7 = com.quizlet.ui.resources.designsystem.generated.j.h;
            q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.d(qVar, f7), 1.0f);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            K kE = AbstractC0409s.e(iVar, false);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            F0 f04 = f0;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            C0418x c0418x = C0418x.a;
            n nVar = n.b;
            androidx.compose.foundation.shape.d dVar5 = dVar2;
            q qVarG = AbstractC0460p.f(c0418x.a(androidx.compose.ui.draw.g.c(nVar, dVar2), androidx.compose.ui.b.e), j5, F.a).g(androidx.compose.foundation.layout.K0.c);
            c0814p.X(-404551159);
            Object objI7 = c0814p.I();
            if (objI7 == v) {
                objI7 = new t(interfaceC0773a03, 21);
                c0814p.i0(objI7);
            }
            c0814p.p(false);
            q qVarL = AbstractC0897s.l(qVarG, (Function1) objI7);
            K kE2 = AbstractC0409s.e(iVar, false);
            int i9 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarL);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            c0814p.X(-323634054);
            W0 w03 = w0;
            boolean zF = c0814p.f(w03);
            Object objI8 = c0814p.I();
            if (zF || objI8 == v) {
                objI8 = new a(w03, 0);
                c0814p.i0(objI8);
            }
            Function0 function0 = (Function0) objI8;
            c0814p.p(false);
            c0814p.X(-323632196);
            W0 w04 = w02;
            boolean zF2 = c0814p.f(w04);
            Object objI9 = c0814p.I();
            if (zF2 || objI9 == v) {
                objI9 = new a(w04, 1);
                c0814p.i0(objI9);
            }
            c0814p.p(false);
            mVar.s();
            C0814p c0814p4 = c0814p;
            AbstractC4810c.a(function0, (Function0) objI9, androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.d(nVar, f7), 1.0f), j6, j4, c0814p4, 0);
            c0814p2 = c0814p4;
            c0814p2.p(true);
            c0814p2.X(-404530905);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                progressBarType = fVar;
                if (progressBarType == f.b) {
                    z = false;
                    a((int) (f04.i() * ((int) (androidx.compose.ui.geometry.e.d(((androidx.compose.ui.geometry.e) interfaceC0773a03.getValue()).a) / Resources.getSystem().getDisplayMetrics().density))), null, c0814p2, 0);
                }
                c0814p2.p(z);
                c0814p2.p(true);
                dVar3 = dVar5;
                j7 = j6;
                j8 = j4;
            } else {
                progressBarType = fVar;
            }
            z = false;
            c0814p2.p(z);
            c0814p2.p(true);
            dVar3 = dVar5;
            j7 = j6;
            j8 = j4;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.learn.ui.progress.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i4 | 1);
                    f fVar2 = progressBarType;
                    androidx.compose.foundation.shape.d dVar6 = dVar3;
                    Function0 function02 = onAnimationFinish;
                    e.b(i, i2, i3, fVar2, qVar, j7, j8, j5, dVar6, function02, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
