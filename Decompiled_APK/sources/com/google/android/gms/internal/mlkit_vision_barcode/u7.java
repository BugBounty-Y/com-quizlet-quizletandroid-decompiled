package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.glance.appwidget.C1217u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class u7 {
    public static final void a(float f, androidx.glance.p pVar, androidx.glance.unit.a aVar, androidx.glance.unit.a aVar2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-12096187);
        if ((((c0814p.c(f) ? 4 : 2) | i | (c0814p.f(pVar) ? 32 : 16) | (c0814p.f(aVar) ? 256 : 128) | (c0814p.f(aVar2) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            int i2 = androidx.glance.appwidget.v0.a;
            c0814p.Y(-1115894518);
            c0814p.Y(1886828752);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(new C1217u(0, 2));
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.appwidget.q0.k);
            C0776c.E(c0814p, Float.valueOf(f), androidx.glance.appwidget.q0.l);
            C0776c.E(c0814p, aVar, androidx.glance.appwidget.q0.m);
            C0776c.E(c0814p, aVar2, androidx.glance.appwidget.q0.n);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.emailconfirmation.ui.composables.p(f, pVar, aVar, aVar2, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.data.model.NotesToValueInfo r11, kotlin.jvm.functions.Function0 r12, androidx.compose.ui.q r13, androidx.compose.runtime.InterfaceC0806l r14, int r15) {
        /*
            Method dump skipped, instructions count: 291
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.u7.b(com.quizlet.data.model.NotesToValueInfo, kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final long c(kotlinx.io.i iVar) {
        Intrinsics.checkNotNullParameter(iVar, "<this>");
        return iVar.c().c;
    }
}
