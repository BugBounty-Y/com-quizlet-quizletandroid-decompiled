package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3777z5;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.features.folders.data.K0 sortType, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        long jF;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(sortType, "sortType");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1977223710);
        int i2 = i | (c0814p.f(sortType) ? 4 : 2) | 48 | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            String strD = AbstractC3106b5.d(c0814p, sortType.a().a);
            com.quizlet.assembly.compose.links.g gVar = com.quizlet.assembly.compose.links.g.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0 = new androidx.compose.foundation.layout.A0(f2, f, f2, f);
            com.quizlet.assembly.compose.cards.c cVar = new com.quizlet.assembly.compose.cards.c(sortType, 11);
            com.quizlet.features.folders.data.D0 d0A = sortType.a();
            c0814p.X(-1165155579);
            Integer num = d0A.d;
            String strD2 = num == null ? null : AbstractC3106b5.d(c0814p, num.intValue());
            c0814p.p(false);
            com.quizlet.features.folders.data.D0 d0A2 = sortType.a();
            c0814p.X(-612766348);
            if (d0A2.c) {
                c0814p.X(-823428949);
                jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e;
                c0814p.p(false);
            } else {
                c0814p.X(-823386851);
                jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                c0814p.p(false);
            }
            AbstractC3777z5.a(strD, nVar3, gVar, a0, new com.quizlet.assembly.compose.links.b(cVar, strD2, androidx.compose.animation.d0.k(c0814p, false, jF)), function0, c0814p, ((i2 << 9) & 458752) | 48, 0);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 21, sortType, nVar2, function0);
        }
    }

    public static final androidx.compose.runtime.saveable.f b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-796079677);
        androidx.compose.runtime.saveable.f fVar = (androidx.compose.runtime.saveable.f) L4.d(new Object[0], androidx.compose.runtime.saveable.f.e, androidx.compose.runtime.saveable.g.b, c0814p, 3072, 4);
        fVar.c = (androidx.compose.runtime.saveable.i) c0814p.j(androidx.compose.runtime.saveable.k.a);
        c0814p.p(false);
        return fVar;
    }
}
