package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N5 {
    public static final void a(com.quizlet.assembly.compose.menu.s sVar, com.quizlet.assembly.compose.modals.x xVar, Function2 function2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1826775392);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(sVar) : c0814p.h(sVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(xVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            T5.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "AssemblyPopupMenu"), xVar, false, null, function0, androidx.compose.runtime.internal.e.e(476069323, new com.quizlet.assembly.compose.menu.l(sVar, xVar, function2, 1), c0814p), c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | 196614 | ((i2 << 3) & 57344), 12);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(sVar, xVar, function2, function0, i, 1);
        }
    }

    public static final void b(com.quizlet.assembly.compose.menu.s sVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1224863445);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(sVar) : c0814p.h(sVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i3 = i & 1;
            Object obj = C0804k.a;
            if (i3 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            Boolean boolValueOf = Boolean.valueOf(K5.a(sVar));
            c0814p.X(1614154280);
            int i4 = i2 & 14;
            int i5 = i4 ^ 6;
            int i6 = i2 & 896;
            boolean zH = ((i5 > 4 && c0814p.h(sVar)) || (i2 & 6) == 4) | (i6 == 256) | c0814p.h(xVarH);
            Object objI = c0814p.I();
            if (zH || objI == obj) {
                objI = new com.quizlet.assembly.compose.menu.v(sVar, xVarH, function0, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.f(c0814p, boolValueOf, (Function2) objI);
            Intrinsics.checkNotNullParameter(sVar, "<this>");
            if (((androidx.compose.runtime.L0) sVar.c).getValue() != com.quizlet.assembly.compose.menu.u.b) {
                com.quizlet.assembly.compose.modals.x.d(xVarH);
                c0814p.X(1614161074);
                boolean z = (i6 == 256) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i5 > 4 && c0814p.h(sVar)) || (i2 & 6) == 4);
                Object objI2 = c0814p.I();
                if (z || objI2 == obj) {
                    objI2 = new com.quizlet.assembly.compose.menu.w(function1, function0, sVar);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                Function2 function2 = (Function2) ((kotlin.reflect.f) objI2);
                c0814p.X(1614161578);
                boolean z2 = (i6 == 256) | ((i5 > 4 && c0814p.h(sVar)) || (i2 & 6) == 4);
                Object objI3 = c0814p.I();
                if (z2 || objI3 == obj) {
                    objI3 = new com.braze.triggers.managers.h(19, function0, sVar);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                a(sVar, xVarH, function2, (Function0) objI3, c0814p, i4);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 3, sVar, function1, function0);
        }
    }

    public static final void c(com.quizlet.assembly.compose.menu.q qVar, com.quizlet.assembly.compose.modals.x xVar, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1693637984);
        int i2 = (c0814p.f(qVar) ? 4 : 2) | i | (c0814p.h(xVar) ? 32 : 16) | (c0814p.h(function2) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z = qVar instanceof com.quizlet.assembly.compose.menu.n;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(1337348369);
                G5.a(((com.quizlet.assembly.compose.menu.n) qVar).a, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.themes.m.b0), ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).l, c0814p, 0);
                c0814p.p(false);
            } else {
                if (!(qVar instanceof com.quizlet.assembly.compose.menu.o)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-926694663, c0814p, false);
                }
                c0814p.X(1337611683);
                androidx.compose.ui.q qVarD = androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.themes.m.b0);
                com.quizlet.assembly.compose.menu.o oVar = (com.quizlet.assembly.compose.menu.o) qVar;
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).j;
                c0814p.X(-926675689);
                boolean zH = ((i2 & 896) == 256) | c0814p.h(xVar);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    objI = new androidx.lifecycle.u0(11, function2, xVar);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                G5.b(oVar, qVarD, l, (Function1) objI, c0814p, 0);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 8, qVar, xVar, function2);
        }
    }

    public static Intent d(Context context, String str) {
        Intent intentB = AbstractC4178x.b(context, "context", context, SearchActivity.class);
        intentB.putExtra("searchQuery", str);
        return intentB;
    }
}
