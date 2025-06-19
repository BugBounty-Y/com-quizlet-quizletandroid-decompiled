package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.q5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3706q5 {
    public static final void a(com.quizlet.ui.models.content.carditem.h userCardModel, androidx.compose.ui.n nVar, int i, Function2 function2, com.quizlet.ui.compose.util.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(userCardModel, "userCardModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-278315983);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.h(userCardModel) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        int i4 = i3 | 48;
        if ((i2 & 384) == 0) {
            i4 |= c0814p2.d(i) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p2.h(function2) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i4 |= (32768 & i2) == 0 ? c0814p2.f(aVar) : c0814p2.h(aVar) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i4 |= c0814p2.h(function0) ? 131072 : 65536;
        }
        if ((74899 & i4) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            c0814p2.X(265081404);
            boolean zH = ((i4 & 7168) == 2048) | c0814p2.h(userCardModel) | ((i4 & 896) == 256);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.quizlet.assembly.compose.cards.a(function2, userCardModel, i, 4);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            R4.a(qVarC, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-165483541, new com.quizlet.assembly.compose.cards.c(userCardModel, 6), c0814p2), c0814p2, 0, 990);
            c0814p = c0814p2;
            if (aVar != null) {
                com.google.android.gms.internal.mlkit_vision_barcode.P5.c(Long.valueOf(userCardModel.a), function0, aVar, c0814p, ((i4 >> 6) & 896) | ((i4 >> 12) & ContentType.LONG_FORM_ON_DEMAND));
            }
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(userCardModel, nVar2, i, function2, aVar, function0, i2, 0);
        }
    }

    public static InterfaceC0388h b(boolean z) {
        if (z) {
            return AbstractC0398m.a;
        }
        C0380d c0380d = AbstractC0398m.a;
        com.quizlet.themes.m.g.s();
        return AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
    }

    public static androidx.compose.foundation.layout.A0 c(boolean z, InterfaceC0806l interfaceC0806l) {
        androidx.compose.foundation.layout.A0 a0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-441901423);
        if (z) {
            c0814p.X(1852533570);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float fL = ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).l();
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            a0 = new androidx.compose.foundation.layout.A0(fL, f, fL, f);
            c0814p.p(false);
        } else {
            c0814p.X(1852724778);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            float fK = ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).k();
            mVar2.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            a0 = new androidx.compose.foundation.layout.A0(fK, f2, fK, f2);
            c0814p.p(false);
        }
        c0814p.p(false);
        return a0;
    }

    public static int d(int i) {
        Set set = androidx.compose.material3.windowsizeclass.c.b;
        return i == 0 ? 1 : 2;
    }

    public static InterfaceC0394k e(boolean z) {
        if (z) {
            return AbstractC0398m.c;
        }
        C0380d c0380d = AbstractC0398m.a;
        com.quizlet.themes.m.g.s();
        return AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
    }
}
