package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
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
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.n5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3214n5 {
    public static final void a(com.google.android.gms.ads.k adView, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(adView, "adView");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1117665865);
        if ((((c0814p.h(adView) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), "adView");
            c0814p.X(-562085389);
            boolean zH = c0814p.h(adView);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.quizletandroid.ui.common.ads.G(adView, 29);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.viewinterop.k.a((Function1) objI, qVarG, null, c0814p, 0, 4);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(adView, nVar, i, 11);
        }
    }

    public static final void b(String text, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1933305729);
        if ((i & 6) == 0) {
            i2 = i | (c0814p2.f(text) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            c0814p2.X(-139303356);
            c0814p2.X(-139303015);
            Object objI = c0814p2.I();
            if (objI == C0804k.a) {
                objI = new com.quizlet.features.emailconfirmation.ui.composables.c(12);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p2.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVar, false, null, (Function0) objI, 6);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p2, 48);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(text, null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i, c0814p2, i3 & 14, 0, 65534);
            c0814p = c0814p2;
            c0814p.X(1774665935);
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(text, qVar, i, 1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0174  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0176  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0167  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.text.L c(androidx.compose.ui.text.L r28, androidx.compose.ui.unit.k r29) {
        /*
            Method dump skipped, instructions count: 399
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5.c(androidx.compose.ui.text.L, androidx.compose.ui.unit.k):androidx.compose.ui.text.L");
    }
}
