package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.learn.data.onboarding.C4551a;
import com.quizlet.learn.data.onboarding.C4552b;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class z4 {
    public static final void a(String setTitle, C4551a uiState, com.quizlet.learn.viewmodel.i viewModel, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1414747739);
        int i2 = i | (c0814p.f(setTitle) ? 4 : 2) | (c0814p.f(uiState) ? 32 : 16) | (c0814p.h(viewModel) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(153243609);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(uiState.b.a);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(153247558, c0814p, false);
            com.quizlet.learn.data.onboarding.u uVar = uiState.c;
            if (objG == v) {
                objG = C0776c.z(uVar.a);
                c0814p.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG;
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "LearnOnboardingBottomSheet");
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(AbstractC0382e.u(qVarG, f).g(androidx.compose.foundation.layout.K0.c), AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1271342485);
            boolean zH = c0814p.h(viewModel);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.learn.ui.onboarding.i(viewModel, 2);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            androidx.compose.material3.Z1.h((Function0) objI2, null, false, null, com.quizlet.learn.ui.onboarding.b.a, c0814p, 196608, 30);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).k;
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).f;
            mVar.k();
            float f2 = com.quizlet.ui.resources.designsystem.generated.h.j;
            mVar.u();
            y4.a(setTitle, l, l2, f2, com.quizlet.ui.resources.designsystem.generated.j.g, null, c0814p, i2 & 14);
            mVar.q();
            androidx.compose.material3.Z1.g(AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, f, 1), DefinitionKt.NO_Float_VALUE, 0L, c0814p, 0, 6);
            AbstractC3549v4.a(null, c0814p, 0);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            c0814p.X(1271369953);
            boolean zH2 = c0814p.h(viewModel);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == v) {
                objI3 = new com.quizlet.learn.ui.onboarding.g(viewModel, interfaceC0773a0, interfaceC0773a02, 2);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p = c0814p;
            AbstractC3561x4.c(uiState.b, uiState.a, qVarC2, (Function1) objI3, c0814p, 384);
            mVar.p();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.j;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f3));
            c0814p.X(1271378758);
            boolean zH3 = c0814p.h(viewModel);
            Object objI4 = c0814p.I();
            if (zH3 || objI4 == v) {
                objI4 = new com.quizlet.learn.ui.onboarding.g(viewModel, interfaceC0773a02, interfaceC0773a0, 3);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            com.quizlet.learn.ui.onboarding.e.a(uVar, (Function1) objI4, c0814p, 6);
            mVar.p();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f3));
            c0814p.X(1271387981);
            boolean zH4 = c0814p.h(viewModel);
            Object objI5 = c0814p.I();
            if (zH4 || objI5 == v) {
                objI5 = new com.quizlet.learn.ui.onboarding.h(viewModel, interfaceC0773a0, interfaceC0773a02, 1);
                c0814p.i0(objI5);
            }
            Function0 function0 = (Function0) objI5;
            c0814p.p(false);
            c0814p.X(1271391957);
            boolean zH5 = c0814p.h(viewModel);
            Object objI6 = c0814p.I();
            if (zH5 || objI6 == v) {
                objI6 = new com.quizlet.learn.ui.onboarding.i(viewModel, 3);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            AbstractC3555w4.a(function0, (Function0) objI6, c0814p, 6);
            c0814p.X(1271394512);
            if (uiState.d) {
                c0814p.X(1271396331);
                boolean zH6 = c0814p.h(viewModel);
                Object objI7 = c0814p.I();
                if (zH6 || objI7 == v) {
                    objI7 = new com.quizlet.learn.ui.onboarding.i(viewModel, 4);
                    c0814p.i0(objI7);
                }
                c0814p.p(false);
                AbstractC3555w4.c((Function0) objI7, c0814p, 6);
            }
            c0814p.p(false);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.ui.onboarding.f(setTitle, uiState, viewModel, qVar2, i, 0);
        }
    }

    public static final void b(com.quizlet.learn.data.onboarding.d uiState, boolean z, Function1 onEvent, androidx.compose.runtime.internal.d content, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(onEvent, "onEvent");
        Intrinsics.checkNotNullParameter(content, "content");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(569687195);
        int i2 = i | (c0814p2.f(uiState) ? 4 : 2) | (c0814p2.h(onEvent) ? 256 : 128);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else if (uiState instanceof C4552b) {
            c0814p2.X(1159272517);
            c0814p = c0814p2;
            AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
            c0814p.p(false);
        } else {
            c0814p = c0814p2;
            if (uiState instanceof C4551a) {
                c0814p.X(1159274587);
                content.invoke(c0814p, 6);
                c0814p.p(false);
            } else {
                if (!(uiState instanceof com.quizlet.learn.data.onboarding.c)) {
                    throw com.google.android.gms.measurement.internal.Z.j(1159270761, c0814p, false);
                }
                c0814p.X(1159276614);
                A4.a((com.quizlet.learn.data.onboarding.c) uiState, z, onEvent, null, c0814p, i2 & 1008);
                c0814p = c0814p;
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(uiState, z, onEvent, content, i, 6);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x0185  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x01c2  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0325  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(java.lang.String r27, com.quizlet.learn.data.onboarding.C4551a r28, com.quizlet.learn.viewmodel.i r29, androidx.compose.ui.q r30, androidx.compose.runtime.InterfaceC0806l r31, int r32) {
        /*
            Method dump skipped, instructions count: 824
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.z4.c(java.lang.String, com.quizlet.learn.data.onboarding.a, com.quizlet.learn.viewmodel.i, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0101 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:78:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(java.lang.String r17, com.quizlet.learn.viewmodel.i r18, kotlin.jvm.functions.Function0 r19, androidx.compose.runtime.InterfaceC0806l r20, int r21, int r22) {
        /*
            Method dump skipped, instructions count: 396
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.z4.d(java.lang.String, com.quizlet.learn.viewmodel.i, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static byte[] e(ArrayDeque arrayDeque, int i) {
        if (arrayDeque.isEmpty()) {
            return new byte[0];
        }
        byte[] bArr = (byte[]) arrayDeque.remove();
        if (bArr.length == i) {
            return bArr;
        }
        int length = i - bArr.length;
        byte[] bArrCopyOf = Arrays.copyOf(bArr, i);
        while (length > 0) {
            byte[] bArr2 = (byte[]) arrayDeque.remove();
            int iMin = Math.min(length, bArr2.length);
            System.arraycopy(bArr2, 0, bArrCopyOf, i - length, iMin);
            length -= iMin;
        }
        return bArrCopyOf;
    }

    public static byte[] f(com.android.volley.toolbox.c cVar) throws IOException {
        ArrayDeque arrayDeque = new ArrayDeque(20);
        int iMin = Math.min(8192, Math.max(128, Integer.highestOneBit(0) * 2));
        int i = 0;
        while (i < 2147483639) {
            int iMin2 = Math.min(iMin, 2147483639 - i);
            byte[] bArr = new byte[iMin2];
            arrayDeque.add(bArr);
            int i2 = 0;
            while (i2 < iMin2) {
                int i3 = cVar.read(bArr, i2, iMin2 - i2);
                if (i3 == -1) {
                    return e(arrayDeque, i);
                }
                i2 += i3;
                i += i3;
            }
            long j = iMin * (iMin < 4096 ? 4 : 2);
            iMin = j > 2147483647L ? SubsamplingScaleImageView.TILE_SIZE_AUTO : j < -2147483648L ? Integer.MIN_VALUE : (int) j;
        }
        if (cVar.read() == -1) {
            return e(arrayDeque, 2147483639);
        }
        throw new OutOfMemoryError("input is too large to fit in a byte array");
    }
}
