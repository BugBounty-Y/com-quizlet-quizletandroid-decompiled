package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.y0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3301y0 {
    public static C0867f a;

    /* JADX WARN: Multi-variable type inference failed */
    public static final void a(String query, SearchType searchType, androidx.compose.ui.n nVar, float f, com.quizlet.search.viewmodels.D d, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        boolean z;
        androidx.compose.foundation.lazy.grid.A a2;
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(query, "query");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(693673428);
        int i3 = i | (c0814p2.f(query) ? 4 : 2) | (c0814p2.f(searchType) ? 32 : 16) | 384 | (c0814p2.c(f) ? 2048 : 1024) | (c0814p2.h(d) ? 16384 : 8192) | (c0814p2.h(cVar) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            androidx.compose.foundation.lazy.grid.A a3 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            int iD = AbstractC3236q0.d(c0814p2);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0C = Q5.c(new androidx.compose.foundation.layout.A0(f2, f2, f2, f2), f);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f2);
            mVar.s();
            C0392j c0392jG2 = AbstractC0398m.g(f2);
            c0814p2.X(-637310980);
            boolean zH = ((i3 & 14) == 4) | c0814p2.h(d);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                z = false;
                objI = new com.quizlet.search.composables.J(d, query, 0 == true ? 1 : 0);
                c0814p2.i0(objI);
            } else {
                z = false;
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(z);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(2008484825, new com.quizlet.search.composables.q(f, 2), c0814p2);
            c0814p2.X(-637289885);
            boolean zD = ((458752 & i3) == 131072) | c0814p2.d(iD) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.f(a3) | c0814p2.h(d);
            Object objI2 = c0814p2.I();
            if (zD || objI2 == v) {
                a2 = a3;
                objI2 = new com.quizlet.quizletandroid.ui.globalnav.composable.d(iD, cVar, searchType, a2, d, 10);
                i2 = iD;
                c0814p2.i0(objI2);
            } else {
                i2 = iD;
                a2 = a3;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3266t5.b(function0, qVarG, 0L, i2, a0C, c0392jG, c0392jG2, a2, dVarE, null, (Function2) objI2, c0814p, 100663296, 516);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.p(query, searchType, nVar3, f, d, cVar, i, 2);
        }
    }

    public static final void b(boolean z, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        long jS;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1008776310);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i4 = i2 | 48;
        if ((i & 384) == 0) {
            i4 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(-1481878367);
                com.quizlet.themes.e.a(c0814p).a.getClass();
                c0814p.X(1342053774);
                i3 = R.drawable.ic_sys_star_filled;
            } else {
                c0814p.X(-1481819033);
                com.quizlet.themes.e.a(c0814p).a.getClass();
                c0814p.X(1882035022);
                i3 = R.drawable.ic_sys_star;
            }
            androidx.compose.ui.graphics.painter.b bVarD = com.google.android.gms.measurement.internal.Z.d(i3, c0814p, 0, false, false);
            String strD = AbstractC3106b5.d(c0814p, R.string.flashcards_content_description_starred);
            C4076a c4076a = C4076a.e;
            if (z) {
                c0814p.X(-1481571591);
                jS = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).G();
                c0814p.p(false);
            } else {
                c0814p.X(-1481504197);
                jS = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).s();
                c0814p.p(false);
            }
            AbstractC3578a5.a(bVarD, strD, nVar3, function0, false, c4076a, null, jS, c0814p, (i4 << 3) & 8064, 80);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.p(z, nVar2, function0, i, 1);
        }
    }
}
