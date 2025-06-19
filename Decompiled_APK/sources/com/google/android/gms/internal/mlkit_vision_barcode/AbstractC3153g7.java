package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.fragment.app.AbstractC1136h0;
import androidx.navigation.compose.C1278k;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.g7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3153g7 {
    public static final void a(Class cls, androidx.compose.ui.q qVar, androidx.fragment.compose.e eVar, Bundle bundle, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1012439764);
        int i2 = i | (c0814p.h(cls) ? 4 : 2);
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i3 = i2 | (c0814p.f(eVar) ? 256 : 128) | (c0814p.h(bundle) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192);
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function1, c0814p);
            int i4 = c0814p.P;
            View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
            c0814p.Y(485393906);
            boolean zF = c0814p.f(view);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (zF || objI == obj) {
                objI = AbstractC1136h0.F(view);
                c0814p.i0(objI);
            }
            AbstractC1136h0 abstractC1136h0 = (AbstractC1136h0) objI;
            c0814p.p(false);
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            c0814p.Y(485398332);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new androidx.fragment.compose.d(i4);
                c0814p.i0(objI2);
            }
            androidx.fragment.compose.d dVar = (androidx.fragment.compose.d) objI2;
            c0814p.p(false);
            androidx.compose.ui.viewinterop.k.a(dVar, qVar, null, c0814p, i3 & ContentType.LONG_FORM_ON_DEMAND, 4);
            Object[] objArr = {abstractC1136h0, dVar, cls, eVar};
            c0814p.Y(485406992);
            boolean zH = ((((i3 & 896) ^ 384) > 256 && c0814p.f(eVar)) || (i3 & 384) == 256) | c0814p.h(abstractC1136h0) | c0814p.h(dVar) | c0814p.h(context) | c0814p.h(cls) | c0814p.h(bundle) | c0814p.d(i4) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zH || objI3 == obj) {
                z = false;
                Object cVar = new androidx.fragment.compose.c(abstractC1136h0, dVar, context, cls, interfaceC0773a0D, eVar, bundle, i4);
                c0814p.i0(cVar);
                objI3 = cVar;
            } else {
                z = false;
            }
            c0814p.p(z);
            C0776c.e(objArr, (Function1) objI3, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.K(cls, qVar, eVar, bundle, function1, i);
        }
    }

    public static final void b(boolean z, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1934309066);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | (c0814p.f(qVar) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            long jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
            androidx.compose.runtime.V v = C0804k.a;
            if (z) {
                c0814p.X(-180018982);
                c0814p.X(-5805614);
                boolean zE = c0814p.e(jF);
                Object objI = c0814p.I();
                if (zE || objI == v) {
                    objI = new com.braze.requests.framework.m(15, jF);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC0460p.b(qVar, (Function1) objI, c0814p, (i3 >> 3) & 14);
                c0814p.p(false);
            } else {
                c0814p.X(-179908808);
                c0814p.X(-5802060);
                boolean zE2 = c0814p.e(jF);
                Object objI2 = c0814p.I();
                if (zE2 || objI2 == v) {
                    objI2 = new com.braze.requests.framework.m(16, jF);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                AbstractC0460p.b(qVar, (Function1) objI2, c0814p, (i3 >> 3) & 14);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.essay.a(z, qVar, i, 0);
        }
    }

    public static final void c(com.quizlet.data.model.T t, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-260878505);
        if ((((c0814p.f(t) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.w();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.f);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0392jG, androidx.compose.ui.b.j, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            mVar.u();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.j.g);
            b(true, qVarK, c0814p, 6);
            b(t.compareTo(com.quizlet.data.model.T.EASY) > 0, qVarK, c0814p, 0);
            b(t.compareTo(com.quizlet.data.model.T.MEDIUM) > 0, qVarK, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(t, i, 12);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:45:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(com.quizlet.data.model.EssayItem r26, androidx.compose.ui.q r27, androidx.compose.runtime.InterfaceC0806l r28, int r29, int r30) {
        /*
            Method dump skipped, instructions count: 297
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7.d(com.quizlet.data.model.EssayItem, androidx.compose.ui.q, androidx.compose.runtime.l, int, int):void");
    }
}
