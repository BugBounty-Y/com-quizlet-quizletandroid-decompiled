package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4094t;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.g6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3627g6 {
    public static final void a(androidx.compose.ui.graphics.painter.b icon, String contentDescription, androidx.compose.ui.q qVar, boolean z, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(contentDescription, "contentDescription");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1918663313);
        int i2 = i | (c0814p.h(icon) ? 4 : 2) | (c0814p.f(contentDescription) ? 32 : 16) | 3072 | (c0814p.g(z) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i3 = i2 >> 6;
            int i4 = i2 << 3;
            AbstractC3635h6.a(icon, contentDescription, function0, androidx.compose.ui.platform.N.G(nVar, contentDescription + "_false"), z, com.quizlet.assembly.compose.tabs.b.a(c0814p), com.quizlet.assembly.compose.tabs.b.b, com.quizlet.assembly.compose.tabs.b.a, com.quizlet.assembly.compose.tabs.b.b(false, c0814p), null, c0814p, (i3 & 7168) | (i4 & ContentType.LONG_FORM_ON_DEMAND) | 113246214 | (i4 & 896) | (i4 & 458752));
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(icon, contentDescription, qVar2, z, function0, i);
        }
    }

    public static final void b(String text, boolean z, androidx.compose.ui.q qVar, boolean z2, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        boolean z3;
        int i3;
        boolean z4;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(869167977);
        int i4 = i | (c0814p.f(text) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 = i4 | 3072;
            z3 = z2;
        } else {
            z3 = z2;
            i3 = i4 | (c0814p.g(z3) ? 2048 : 1024);
        }
        int i6 = i3 | (c0814p.h(function0) ? 16384 : 8192);
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            z4 = z3;
        } else {
            z4 = i5 != 0 ? true : z3;
            int i7 = i6 << 3;
            AbstractC3635h6.b(z, text, function0, androidx.compose.ui.platform.N.G(qVar, text + "_" + z), z4, null, 0, 0, null, null, com.quizlet.assembly.compose.tabs.b.a(c0814p), com.quizlet.assembly.compose.tabs.b.b, com.quizlet.assembly.compose.tabs.b.b(z, c0814p), null, c0814p, ((i6 >> 6) & 896) | ((i6 >> 3) & 14) | (i7 & ContentType.LONG_FORM_ON_DEMAND) | (57344 & i7), 48, 9184);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.tabs.c(text, z, qVar, z4, function0, i, i2);
        }
    }

    public static final void c(com.quizlet.quizletandroid.ui.globalnav.composable.n onClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1066302919);
        int i2 = (c0814p.h(onClick) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.accepting_tos_privacy_policy);
            com.quizlet.themes.m.g.u();
            AbstractC3586b5.a(strD, AbstractC0382e.w(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 1).g(new HorizontalAlignElement(androidx.compose.ui.b.n)), onClick, false, C4076a.m, C4094t.a, null, null, null, c0814p, (i2 << 6) & 896, 968);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(onClick, nVar2, i, 23);
        }
    }
}
