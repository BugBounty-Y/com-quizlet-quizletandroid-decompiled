package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.k6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3659k6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.material3.L3 snackbarData, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(snackbarData, "snackbarData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(517378358);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(snackbarData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 432;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            c(snackbarData.a.a(), c0814p, i3 & 1008);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(snackbarData, nVar, i, 1);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(726580566);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(null) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVar, 12);
            com.quizlet.themes.m.g.c();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.T3.a(qVarU, null, null, dVarA, ((com.quizlet.themes.b) c0814p.j(b)).h, ((com.quizlet.themes.b) c0814p.j(b)).i, 0L, 0L, dVar, c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 21) & 1879048192), 396);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(qVar, dVar, i);
        }
    }

    public static final void c(String message, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        Intrinsics.checkNotNullParameter(message, "message");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2017426188);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(message) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(nVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(null) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = i2 >> 3;
            b(nVar, androidx.compose.runtime.internal.e.e(-1438596454, new com.quizlet.assembly.compose.input.i(message, 5), c0814p), c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 14) | 384);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.f(message, i);
        }
    }
}
