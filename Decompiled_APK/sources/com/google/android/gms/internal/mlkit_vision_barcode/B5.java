package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.res.Configuration;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B5 {
    /* JADX WARN: Removed duplicated region for block: B:109:0x0225  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0320  */
    /* JADX WARN: Removed duplicated region for block: B:128:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00d2  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01ab  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.lang.String r41, java.lang.String r42, java.lang.String r43, int r44, boolean r45, java.lang.String r46, androidx.compose.ui.q r47, kotlin.jvm.functions.Function0 r48, androidx.compose.runtime.InterfaceC0806l r49, int r50, int r51) {
        /*
            Method dump skipped, instructions count: 826
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.B5.a(java.lang.String, java.lang.String, java.lang.String, int, boolean, java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(Function0 onSwipeLeft, Function0 onSwipeRight, androidx.compose.ui.q qVar, com.quizlet.ui.compose.N n, Function1 function1, Function1 function12, Function2 function2, Function2 function22, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        Object c;
        androidx.compose.runtime.V v;
        kotlinx.coroutines.C c2;
        final float f;
        Object h;
        C0814p c0814p;
        int i3;
        final C0238e c0238e;
        boolean z;
        Function2 function23;
        C0238e c0238e2;
        androidx.compose.ui.q qVar2;
        Function2 function24;
        Intrinsics.checkNotNullParameter(onSwipeLeft, "onSwipeLeft");
        Intrinsics.checkNotNullParameter(onSwipeRight, "onSwipeRight");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1259464326);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(onSwipeLeft) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(onSwipeRight) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= (i & 4096) == 0 ? c0814p2.f(n) : c0814p2.h(n) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            function13 = function1;
            i2 |= c0814p2.h(function13) ? 16384 : 8192;
        } else {
            function13 = function1;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function12) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i2 |= c0814p2.h(function2) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i2 |= c0814p2.h(function22) ? 8388608 : 4194304;
        }
        if ((i2 & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            function23 = function2;
            function24 = function22;
            c0814p = c0814p2;
            qVar2 = qVar;
        } else {
            androidx.compose.runtime.V v2 = C0804k.a;
            c0814p2.X(-1660917754);
            Object objI = c0814p2.I();
            if (objI == v2) {
                objI = AbstractC0240f.a(DefinitionKt.NO_Float_VALUE);
                c0814p2.i0(objI);
            }
            C0238e c0238e3 = (C0238e) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1660916282, c0814p2, false);
            if (objG == v2) {
                objG = AbstractC0240f.a(DefinitionKt.NO_Float_VALUE);
                c0814p2.i0(objG);
            }
            C0238e c0238e4 = (C0238e) objG;
            c0814p2.p(false);
            float f2 = ((Configuration) c0814p2.j(AndroidCompositionLocals_androidKt.a)).screenWidthDp;
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p2.j(AbstractC0955m0.f);
            c0814p2.X(-1660911223);
            boolean zC = c0814p2.c(f2);
            Object objI2 = c0814p2.I();
            if (zC || objI2 == v2) {
                objI2 = Float.valueOf(bVar.c0(f2));
                c0814p2.i0(objI2);
            }
            float fFloatValue = ((Number) objI2).floatValue();
            c0814p2.p(false);
            c0814p2.X(-1660908410);
            boolean zC2 = c0814p2.c(fFloatValue);
            Object objI3 = c0814p2.I();
            if (zC2 || objI3 == v2) {
                objI3 = Float.valueOf(0.35f * fFloatValue);
                c0814p2.i0(objI3);
            }
            float fFloatValue2 = ((Number) objI3).floatValue();
            c0814p2.p(false);
            Object objI4 = c0814p2.I();
            if (objI4 == v2) {
                objI4 = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p2), c0814p2);
            }
            kotlinx.coroutines.C c3 = ((C0839z) objI4).a;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(onSwipeRight, c0814p2);
            c0814p2.X(-1660901056);
            boolean zH = ((i2 & 7168) == 2048 || ((i2 & 4096) != 0 && c0814p2.h(n))) | c0814p2.h(c3) | c0814p2.h(c0238e3) | c0814p2.c(fFloatValue) | c0814p2.h(c0238e4) | c0814p2.f(interfaceC0773a0D);
            Object objI5 = c0814p2.I();
            if (zH || objI5 == v2) {
                v = v2;
                c2 = c3;
                c = new com.quizlet.ui.compose.C(n, c2, c0238e3, fFloatValue, c0238e4, interfaceC0773a0D, null);
                f = fFloatValue;
                c0814p2.i0(c);
            } else {
                c = objI5;
                v = v2;
                f = fFloatValue;
                c2 = c3;
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, n, (Function2) c);
            Unit unit = Unit.a;
            c0814p2.X(-1660863568);
            boolean zH2 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.h(c0238e3) | c0814p2.c(fFloatValue2) | c0814p2.h(c2) | c0814p2.c(f) | ((i2 & 14) == 4) | c0814p2.h(c0238e4) | ((57344 & i2) == 16384) | ((458752 & i2) == 131072);
            Object objI6 = c0814p2.I();
            if (zH2 || objI6 == v) {
                c0814p = c0814p2;
                i3 = i2;
                kotlinx.coroutines.C c4 = c2;
                c0238e = c0238e3;
                z = false;
                function23 = function2;
                float f3 = f;
                c0238e2 = c0238e4;
                h = new com.quizlet.ui.compose.H(c0238e, fFloatValue2, c4, f3, onSwipeRight, onSwipeLeft, c0238e2, function13, function12, null);
                f = f3;
                c0814p.i0(h);
            } else {
                function23 = function2;
                h = objI6;
                c0814p = c0814p2;
                i3 = i2;
                c0238e2 = c0238e4;
                c0238e = c0238e3;
                z = false;
            }
            c0814p.p(z);
            qVar2 = qVar;
            androidx.compose.ui.q qVarA = androidx.compose.ui.input.pointer.v.a(qVar2, unit, (Function2) h);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, z);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarA);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            function23.invoke(c0814p, Integer.valueOf((i3 >> 18) & 14));
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(1366532261);
            boolean zH3 = c0814p.h(c0238e) | c0814p.h(c0238e2);
            Object objI7 = c0814p.I();
            if (zH3 || objI7 == v) {
                objI7 = new com.quizlet.quizletandroid.ui.subject.f(4, c0238e, c0238e2);
                c0814p.i0(objI7);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarR = AbstractC0382e.r(nVar, (Function1) objI7);
            c0814p.X(1366535237);
            boolean zH4 = c0814p.h(c0238e) | c0814p.c(f);
            Object objI8 = c0814p.I();
            if (zH4 || objI8 == v) {
                objI8 = new Function1() { // from class: com.quizlet.ui.compose.A
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        androidx.compose.ui.graphics.S graphicsLayer = (androidx.compose.ui.graphics.S) obj;
                        Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                        graphicsLayer.k((((Number) c0238e.d()).floatValue() / f) * 8.0f);
                        return Unit.a;
                    }
                };
                c0814p.i0(objI8);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarP = androidx.compose.ui.graphics.F.p(qVarR, (Function1) objI8);
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarP);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            function24 = function22;
            function24.invoke(c0814p, Integer.valueOf((i3 >> 21) & 14));
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.E(onSwipeLeft, onSwipeRight, qVar2, n, function1, function12, function23, function24, i);
        }
    }

    public static final void c(kotlinx.coroutines.C c, C0238e c0238e, C0238e c0238e2, Function1 function1, Function1 function12) {
        kotlinx.coroutines.E.A(c, null, null, new com.quizlet.ui.compose.I(c0238e, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new com.quizlet.ui.compose.J(c0238e2, null), 3);
        Float fValueOf = Float.valueOf(DefinitionKt.NO_Float_VALUE);
        function1.invoke(fValueOf);
        function12.invoke(fValueOf);
    }

    public static final Object d(C0238e c0238e, float f, kotlin.coroutines.jvm.internal.i iVar) {
        Object objC = C0238e.c(c0238e, new Float((((Number) c0238e.d()).floatValue() / Math.abs(((Number) c0238e.d()).floatValue())) * f * 2), AbstractC0240f.r(300, 0, null, 6), null, iVar, 12);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x005a, code lost:
    
        if (r7.f(r6, r0) == r1) goto L21;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object e(androidx.compose.animation.core.C0238e r6, androidx.compose.animation.core.C0238e r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            boolean r0 = r8 instanceof com.quizlet.ui.compose.K
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.ui.compose.K r0 = (com.quizlet.ui.compose.K) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.ui.compose.K r0 = new com.quizlet.ui.compose.K
            r0.<init>(r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L39
            if (r2 == r5) goto L33
            if (r2 != r4) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5d
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.compose.animation.core.e r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4c
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Float r8 = new java.lang.Float
            r8.<init>(r3)
            r0.j = r7
            r0.l = r5
            java.lang.Object r6 = r6.f(r8, r0)
            if (r6 != r1) goto L4c
            goto L5c
        L4c:
            java.lang.Float r6 = new java.lang.Float
            r6.<init>(r3)
            r8 = 0
            r0.j = r8
            r0.l = r4
            java.lang.Object r6 = r7.f(r6, r0)
            if (r6 != r1) goto L5d
        L5c:
            return r1
        L5d:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.B5.e(androidx.compose.animation.core.e, androidx.compose.animation.core.e, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final long f(long j, long j2) {
        int iC;
        int iE = androidx.compose.ui.text.K.e(j);
        int iD = androidx.compose.ui.text.K.d(j);
        if (androidx.compose.ui.text.K.e(j2) >= androidx.compose.ui.text.K.d(j) || androidx.compose.ui.text.K.e(j) >= androidx.compose.ui.text.K.d(j2)) {
            if (iD > androidx.compose.ui.text.K.e(j2)) {
                iE -= androidx.compose.ui.text.K.c(j2);
                iC = androidx.compose.ui.text.K.c(j2);
                iD -= iC;
            }
        } else if (androidx.compose.ui.text.K.e(j2) > androidx.compose.ui.text.K.e(j) || androidx.compose.ui.text.K.d(j) > androidx.compose.ui.text.K.d(j2)) {
            if (androidx.compose.ui.text.K.e(j) > androidx.compose.ui.text.K.e(j2) || androidx.compose.ui.text.K.d(j2) > androidx.compose.ui.text.K.d(j)) {
                int iE2 = androidx.compose.ui.text.K.e(j2);
                if (iE >= androidx.compose.ui.text.K.d(j2) || iE2 > iE) {
                    iD = androidx.compose.ui.text.K.e(j2);
                } else {
                    iE = androidx.compose.ui.text.K.e(j2);
                    iC = androidx.compose.ui.text.K.c(j2);
                }
            } else {
                iC = androidx.compose.ui.text.K.c(j2);
            }
            iD -= iC;
        } else {
            iE = androidx.compose.ui.text.K.e(j2);
            iD = iE;
        }
        return AbstractC3205m5.c(iE, iD);
    }
}
