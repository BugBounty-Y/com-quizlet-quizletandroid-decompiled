package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.g6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3152g6 {
    /* JADX WARN: Removed duplicated region for block: B:65:0x0184  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.infra.folder.menu.data.b r34, androidx.compose.ui.q r35, boolean r36, boolean r37, boolean r38, kotlinx.collections.immutable.c r39, com.quizlet.ui.compose.C4832z r40, kotlin.jvm.functions.Function1 r41, kotlin.jvm.functions.Function1 r42, kotlin.jvm.functions.Function1 r43, androidx.compose.runtime.InterfaceC0806l r44, int r45) {
        /*
            Method dump skipped, instructions count: 703
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6.a(com.quizlet.features.infra.folder.menu.data.b, androidx.compose.ui.q, boolean, boolean, boolean, kotlinx.collections.immutable.c, com.quizlet.ui.compose.z, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static final void b(androidx.appcompat.app.y controlState, androidx.compose.ui.q qVar, Integer num, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        Integer num2;
        int i4;
        Integer num3;
        androidx.compose.runtime.V v;
        androidx.compose.ui.n nVar;
        boolean z;
        androidx.compose.ui.q qVar3;
        Integer num4;
        Intrinsics.checkNotNullParameter(controlState, "controlState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(242087020);
        int i5 = i | (c0814p.h(controlState) ? 4 : 2);
        int i6 = i2 & 2;
        if (i6 != 0) {
            i3 = i5 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i5 | (c0814p.f(qVar2) ? 32 : 16);
        }
        int i7 = i2 & 4;
        if (i7 != 0) {
            i4 = i3 | 384;
            num2 = num;
        } else {
            num2 = num;
            i4 = i3 | (c0814p.f(num2) ? 256 : 128);
        }
        int i8 = i4 | (c0814p.h(function1) ? 2048 : 1024);
        if ((i8 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            num4 = num2;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (i6 != 0) {
                qVar2 = nVar2;
            }
            Integer num5 = i7 != 0 ? null : num2;
            androidx.compose.runtime.V v2 = C0804k.a;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i9 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar2);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1151061784);
            if (num5 != null) {
                num3 = num5;
                z = false;
                nVar = nVar2;
                v = v2;
                androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, num5.intValue()), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, c0814p, 0, 0, 65530);
                c0814p = c0814p;
            } else {
                num3 = num5;
                v = v2;
                nVar = nVar2;
                z = false;
            }
            c0814p.p(z);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(1151074831);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v3 = v;
            if (objI == v3) {
                objI = new com.quizlet.qutils.android.f(25);
                c0814p.i0(objI);
            }
            Function1 function12 = (Function1) objI;
            c0814p.p(z);
            c0814p.X(1151076686);
            boolean zH = ((i8 & 7168) == 2048 ? true : z) | c0814p.h(controlState);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v3) {
                objI2 = new com.quizlet.quizletandroid.ui.subject.f(5, controlState, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(z);
            androidx.compose.ui.viewinterop.k.a(function12, qVarY, (Function1) objI2, c0814p, 6, 0);
            c0814p.p(true);
            qVar3 = qVar2;
            num4 = num3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(controlState, qVar3, num4, function1, i, i2);
        }
    }

    public static float[] c(float[] fArr, int i) {
        if (i < 0) {
            throw new IllegalArgumentException();
        }
        int length = fArr.length;
        if (length < 0) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int iMin = Math.min(i, length);
        float[] fArr2 = new float[i];
        System.arraycopy(fArr, 0, fArr2, 0, iMin);
        return fArr2;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0096 A[Catch: NumberFormatException -> 0x00aa, LOOP:3: B:25:0x0068->B:44:0x0096, LOOP_END, TryCatch #0 {NumberFormatException -> 0x00aa, blocks: (B:22:0x0054, B:25:0x0068, B:27:0x006e, B:31:0x007a, B:44:0x0096, B:46:0x009c, B:52:0x00b1, B:53:0x00b4), top: B:68:0x0054 }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x009c A[Catch: NumberFormatException -> 0x00aa, TryCatch #0 {NumberFormatException -> 0x00aa, blocks: (B:22:0x0054, B:25:0x0068, B:27:0x006e, B:31:0x007a, B:44:0x0096, B:46:0x009c, B:52:0x00b1, B:53:0x00b4), top: B:68:0x0054 }] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00b1 A[Catch: NumberFormatException -> 0x00aa, TryCatch #0 {NumberFormatException -> 0x00aa, blocks: (B:22:0x0054, B:25:0x0068, B:27:0x006e, B:31:0x007a, B:44:0x0096, B:46:0x009c, B:52:0x00b1, B:53:0x00b4), top: B:68:0x0054 }] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00d7 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0095 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.core.graphics.g[] d(java.lang.String r17) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6.d(java.lang.String):androidx.core.graphics.g[]");
    }

    public static androidx.core.graphics.g[] e(androidx.core.graphics.g[] gVarArr) {
        androidx.core.graphics.g[] gVarArr2 = new androidx.core.graphics.g[gVarArr.length];
        for (int i = 0; i < gVarArr.length; i++) {
            gVarArr2[i] = new androidx.core.graphics.g(gVarArr[i]);
        }
        return gVarArr2;
    }
}
