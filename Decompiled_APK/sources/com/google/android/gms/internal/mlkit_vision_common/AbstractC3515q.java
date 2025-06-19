package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.provider.Settings;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.airbnb.lottie.compose.LottieAnimationSizeElement;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3515q {
    public static final void a(com.airbnb.lottie.h hVar, androidx.compose.ui.q qVar, int i, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, InterfaceC0806l interfaceC0806l, int i2, int i3, int i4) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1331239405);
        int i5 = (i4 & 64) != 0 ? 1 : i;
        androidx.compose.ui.d dVar2 = (i4 & 32768) != 0 ? androidx.compose.ui.b.e : dVar;
        InterfaceC0889j interfaceC0889j2 = (i4 & 65536) != 0 ? C0888i.b : interfaceC0889j;
        c0814p.Y(683659508);
        com.airbnb.lottie.compose.l lVar = com.airbnb.lottie.compose.l.a;
        if (i5 <= 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i5, "Iterations must be a positive number (", ").").toString());
        }
        if (Float.isInfinite(1.0f) || Float.isNaN(1.0f)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.i("Speed must be a finite number. It is ", 1.0f, ".").toString());
        }
        c0814p.Y(2024497114);
        c0814p.Y(-610207850);
        Object objI = c0814p.I();
        Object obj = C0804k.a;
        if (objI == obj) {
            objI = new com.airbnb.lottie.compose.h();
            c0814p.i0(objI);
        }
        com.airbnb.lottie.compose.h hVar2 = (com.airbnb.lottie.compose.h) objI;
        c0814p.p(false);
        c0814p.p(false);
        c0814p.Y(-180606964);
        Object objI2 = c0814p.I();
        if (objI2 == obj) {
            objI2 = C0776c.z(true);
            c0814p.i0(objI2);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI2;
        c0814p.p(false);
        c0814p.Y(-180606834);
        Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        Matrix matrix = com.airbnb.lottie.utils.i.a;
        float f = 1.0f / Settings.Global.getFloat(context.getContentResolver(), "animator_duration_scale", 1.0f);
        c0814p.p(false);
        C0776c.h(new Object[]{hVar, true, null, Float.valueOf(f), Integer.valueOf(i5)}, new com.airbnb.lottie.compose.a(hVar2, hVar, i5, f, lVar, interfaceC0773a0, null), c0814p);
        c0814p.p(false);
        c0814p.Y(185157769);
        boolean zF = c0814p.f(hVar2);
        Object objI3 = c0814p.I();
        if (zF || objI3 == obj) {
            objI3 = new com.airbnb.lottie.compose.f(hVar2, 3);
            c0814p.i0(objI3);
        }
        c0814p.p(false);
        int i6 = i3 >> 15;
        b(hVar, (Function0) objI3, qVar, dVar2, interfaceC0889j2, c0814p, ((i2 << 3) & 896) | 1073741832, (i6 & 14) | 32768 | (i6 & ContentType.LONG_FORM_ON_DEMAND));
        androidx.compose.ui.d dVar3 = dVar2;
        InterfaceC0889j interfaceC0889j3 = interfaceC0889j2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.airbnb.lottie.compose.j(hVar, qVar, i5, dVar3, interfaceC0889j3, i2, i3, i4);
        }
    }

    public static final void b(com.airbnb.lottie.h hVar, Function0 progress, androidx.compose.ui.q qVar, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Intrinsics.checkNotNullParameter(progress, "progress");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(382909894);
        c0814p.Y(185152185);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            objI = new com.airbnb.lottie.u();
            c0814p.i0(objI);
        }
        com.airbnb.lottie.u uVar = (com.airbnb.lottie.u) objI;
        c0814p.p(false);
        c0814p.Y(185152232);
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = new Matrix();
            c0814p.i0(objI2);
        }
        Matrix matrix = (Matrix) objI2;
        c0814p.p(false);
        c0814p.Y(185152312);
        boolean zF = c0814p.f(hVar);
        Object objI3 = c0814p.I();
        if (zF || objI3 == v) {
            objI3 = C0776c.z(null);
            c0814p.i0(objI3);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI3;
        c0814p.p(false);
        c0814p.Y(185152364);
        if (hVar == null || hVar.b() == DefinitionKt.NO_Float_VALUE) {
            AbstractC0409s.a(qVar, c0814p, (i >> 6) & 14);
            c0814p.p(false);
            C0813o0 c0813o0R = c0814p.r();
            if (c0813o0R != null) {
                c0813o0R.d = new com.airbnb.lottie.compose.i(hVar, progress, qVar, dVar, interfaceC0889j, i, i2, 0);
                return;
            }
            return;
        }
        c0814p.p(false);
        Rect rect = hVar.k;
        Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        int iWidth = rect.width();
        int iHeight = rect.height();
        Intrinsics.checkNotNullParameter(qVar, "<this>");
        AbstractC0460p.b(qVar.g(new LottieAnimationSizeElement(iWidth, iHeight)), new androidx.compose.material3.H0(rect, interfaceC0889j, dVar, matrix, uVar, hVar, context, progress, interfaceC0773a0, 2), c0814p, 0);
        C0813o0 c0813o0R2 = c0814p.r();
        if (c0813o0R2 != null) {
            c0813o0R2.d = new com.airbnb.lottie.compose.i(hVar, progress, qVar, dVar, interfaceC0889j, i, i2, 1);
        }
    }

    public static final void c(androidx.compose.ui.graphics.painter.b icon, String buttonTitle, androidx.compose.ui.q qVar, Function0 function0, com.quizlet.data.model.A0 a0, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(buttonTitle, "buttonTitle");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(947659265);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(icon) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(buttonTitle) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(a0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            z2 = z;
            i2 |= c0814p.g(z2) ? 131072 : 65536;
        } else {
            z2 = z;
        }
        if ((i2 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.material3.Z1.c(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), null, androidx.compose.material3.Z1.o(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), 0L, 0L, c0814p, 0, 14), androidx.compose.material3.Z1.p(com.quizlet.themes.m.S, 62), null, androidx.compose.runtime.internal.e.e(628280399, new com.quizlet.explanations.questiondetail.ui.composables.n(function0, z2, icon, buttonTitle, a0), c0814p), c0814p, 196608, 18);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.diagrams.ui.f(icon, buttonTitle, qVar, function0, a0, z, i);
        }
    }
}
