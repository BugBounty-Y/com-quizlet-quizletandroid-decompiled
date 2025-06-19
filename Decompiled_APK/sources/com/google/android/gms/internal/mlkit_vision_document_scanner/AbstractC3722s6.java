package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.android.billingclient.api.Purchase;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.s6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3722s6 {
    public static final void a(androidx.compose.ui.graphics.painter.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.graphics.painter.b bVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(169882519);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            bVar2 = bVar;
        } else {
            bVar2 = bVar;
            AbstractC0460p.c(bVar2, null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(androidx.compose.ui.n.b, com.quizlet.themes.m.n0), "learn_round_summary_header_image_tag"), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, (i2 & 14) | 48, 120);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.t(bVar2, i, 4);
        }
    }

    public static final void b(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(922485608);
        if ((i & 6) == 0) {
            i2 = i | (c0814p2.f(str) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(str, qVar, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).f(), c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(str, qVar, i, 5);
        }
    }

    public static final void c(String motivationalTextHeader, androidx.compose.ui.q qVar, androidx.compose.ui.graphics.painter.b bVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.graphics.painter.b bVar2;
        int i4;
        androidx.compose.ui.graphics.painter.b bVar3;
        Intrinsics.checkNotNullParameter(motivationalTextHeader, "motivationalTextHeader");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1257388566);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.f(motivationalTextHeader) ? 4 : 2);
        } else {
            i3 = i;
        }
        int i5 = i3 | (c0814p.f(qVar) ? 32 : 16);
        int i6 = i2 & 4;
        if (i6 != 0) {
            i4 = i5 | 384;
            bVar2 = bVar;
        } else {
            bVar2 = bVar;
            i4 = i5 | (c0814p.h(bVar2) ? 256 : 128);
        }
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            bVar3 = bVar2;
        } else {
            androidx.compose.ui.graphics.painter.b bVar4 = i6 != 0 ? null : bVar2;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            com.quizlet.themes.m.g.s();
            b(motivationalTextHeader, androidx.compose.ui.platform.N.G(AbstractC0382e.y(layoutWeightElement, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "learn_round_summary_header_text_tag"), c0814p, i4 & 14);
            c0814p.X(1992662199);
            if (bVar4 != null) {
                a(bVar4, c0814p, (i4 >> 6) & 14);
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
            bVar3 = bVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i, i2, 10, motivationalTextHeader, qVar, bVar3);
        }
    }

    public static final String d(Purchase purchase) {
        Intrinsics.checkNotNullParameter(purchase, "<this>");
        ArrayList arrayListA = purchase.a();
        Intrinsics.checkNotNullExpressionValue(arrayListA, "getProducts(...)");
        Object objL = CollectionsKt.L(arrayListA);
        Intrinsics.checkNotNullExpressionValue(objL, "first(...)");
        return (String) objL;
    }
}
