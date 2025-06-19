package com.quizlet.quizletandroid.ui.widgets.ui.theme;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.unit.m;
import androidx.glance.text.g;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;

/* loaded from: classes3.dex */
public final class d {
    public static final d a = new d();

    public static g a(m mVar, androidx.glance.text.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1387900429);
        if ((i & 2) != 0) {
            bVar = new androidx.glance.text.b(400);
        }
        androidx.glance.color.a aVarB = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.b(c.a, c0814p);
        androidx.glance.text.c cVar = new androidx.glance.text.c(4);
        if ((96 & 2) != 0) {
            mVar = null;
        }
        if ((96 & 4) != 0) {
            bVar = null;
        }
        if ((96 & 16) != 0) {
            cVar = null;
        }
        g gVar = new g(aVarB, mVar, bVar, cVar);
        c0814p.p(false);
        return gVar;
    }

    public static g b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1117928247);
        g gVarA = a(new m(S5.g(12)), null, c0814p, 6);
        c0814p.p(false);
        return gVarA;
    }

    public static g c(C0814p c0814p) {
        c0814p.X(252979977);
        g gVarA = a(new m(S5.g(32)), new androidx.glance.text.b(700), c0814p, 4);
        c0814p.p(false);
        return gVarA;
    }

    public static g d(C0814p c0814p) {
        c0814p.X(472902697);
        g gVarA = a(new m(S5.g(16)), null, c0814p, 6);
        c0814p.p(false);
        return gVarA;
    }

    public static g e(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(830492121);
        g gVarA = a(new m(S5.g(16)), new androidx.glance.text.b(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), c0814p, 4);
        c0814p.p(false);
        return gVarA;
    }

    public static g f(C0814p c0814p) {
        c0814p.X(-1256836779);
        g gVarA = a(new m(S5.g(12)), new androidx.glance.text.b(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), c0814p, 4);
        c0814p.p(false);
        return gVarA;
    }
}
