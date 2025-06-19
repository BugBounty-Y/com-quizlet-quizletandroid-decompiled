package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.AbstractC0996h;
import androidx.compose.ui.text.AbstractC1013n;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import com.braze.C1483i;
import com.comscore.streaming.ContentType;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3227p0 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function1 function1, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-917547298);
        int i2 = i | (c0814p.d(R.string.flashcards_settings_sorting_label) ? 4 : 2) | (c0814p.d(R.string.flashcards_settings_sorting_description) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(1762010484);
            int i3 = i2 & 896;
            boolean z2 = i3 == 256;
            Object objI = c0814p.I();
            if (z2 || objI == obj) {
                objI = new C1483i(z, 10);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            Boolean boolValueOf = Boolean.valueOf(z);
            c0814p.X(-178284237);
            boolean zF = c0814p.f(interfaceC0773a0) | (i3 == 256);
            Object objI2 = c0814p.I();
            if (zF || objI2 == obj) {
                objI2 = new com.quizlet.features.flashcards.settings.ui.i(z, interfaceC0773a0, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, boolValueOf, (Function2) objI2);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarC2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            String strD = AbstractC3106b5.d(c0814p, R.string.flashcards_settings_sorting_label);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.b;
            androidx.compose.material3.Q4.b(strD, layoutWeightElement, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).j, c0814p, 0, 0, 65528);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "toggle");
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            c0814p.X(-824767754);
            boolean zF2 = c0814p.f(interfaceC0773a0) | ((i2 & 57344) == 16384);
            Object objI3 = c0814p.I();
            if (zF2 || objI3 == obj) {
                objI3 = new com.quizlet.features.flashcards.settings.ui.e(1, interfaceC0773a0, function1);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.S4.a(zBooleanValue, qVarG, (Function1) objI3, false, c0814p, 48, 8);
            c0814p.p(true);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.flashcards_settings_sorting_description), null, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).p, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.c(z, qVar, function1, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v22 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r0v9, types: [boolean, int] */
    public static final void b(String query, SearchType searchType, androidx.compose.ui.n nVar, float f, com.quizlet.search.viewmodels.u uVar, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        ?? r0;
        androidx.compose.foundation.lazy.grid.A a;
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(query, "query");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1060331275);
        int i3 = i | (c0814p2.f(query) ? 4 : 2) | (c0814p2.f(searchType) ? 32 : 16) | 384 | (c0814p2.c(f) ? 2048 : 1024) | (c0814p2.h(uVar) ? 16384 : 8192) | (c0814p2.h(function2) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar3 = nVar;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            Object obj = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            androidx.compose.foundation.lazy.grid.A a2 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
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
            c0814p2.X(-1277518637);
            boolean zH = ((i3 & 14) == 4) | c0814p2.h(uVar);
            Object objI = c0814p2.I();
            if (zH || objI == obj) {
                r0 = 0;
                objI = new com.quizlet.search.composables.o(uVar, query, 0);
                c0814p2.i0(objI);
            } else {
                r0 = 0;
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(r0);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(241746896, new com.quizlet.search.composables.q(f, r0), c0814p2);
            c0814p2.X(-1277497557);
            boolean zD = ((458752 & i3) == 131072) | c0814p2.d(iD) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.f(a2) | c0814p2.h(uVar);
            Object objI2 = c0814p2.I();
            if (zD || objI2 == obj) {
                a = a2;
                i2 = iD;
                objI2 = new com.quizlet.quizletandroid.ui.globalnav.composable.d(i2, function2, searchType, a, uVar, 8);
                c0814p2.i0(objI2);
            } else {
                a = a2;
                i2 = iD;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3266t5.b(function0, qVarG, 0L, i2, a0C, c0392jG, c0392jG2, a, dVarE, null, (Function2) objI2, c0814p, 100663296, 516);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.p(query, searchType, nVar3, f, uVar, function2, i, 0);
        }
    }

    public static final boolean c(C0995g c0995g) {
        int length = c0995g.a.length();
        List list = c0995g.d;
        if (list != null) {
            int size = list.size();
            for (int i = 0; i < size; i++) {
                C0985e c0985e = (C0985e) list.get(i);
                if ((c0985e.a instanceof AbstractC1013n) && AbstractC0996h.c(0, length, c0985e.b, c0985e.c)) {
                    return true;
                }
            }
        }
        return false;
    }
}
