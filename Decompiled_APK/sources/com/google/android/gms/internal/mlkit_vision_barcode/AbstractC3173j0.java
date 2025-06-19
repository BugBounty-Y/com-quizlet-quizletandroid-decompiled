package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3173j0 {
    public static final void a(com.quizlet.features.flashcards.data.q qVar, androidx.compose.ui.q qVar2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1029406573);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function02) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "FlashcardsSummaryScreen");
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1015403569, new androidx.navigation.compose.o(15, qVar, function0), c0814p2);
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVarG, dVarE, null, null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(1091613436, new com.quizlet.assembly.compose.input.m(7, qVar, function02), c0814p2), c0814p, 805306416, 252);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(qVar, qVar2, function0, function02, i, 5);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, androidx.compose.foundation.layout.z0 z0Var, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1287875327);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= c0814p.f(z0Var) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarT = AbstractC0382e.t(nVar, z0Var);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            androidx.compose.ui.q qVarG = qVarT.g(fillElement);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0386g c0386g = AbstractC0398m.e;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(fillElement, 1.0f);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarA);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            qVar2 = nVar;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.search_empty_text), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).g, c0814p, 0, 0, 65018);
            c0814p = c0814p;
            c0814p.p(true);
            com.quizlet.themes.m.g.s();
            AbstractC3200m0.a(AbstractC0382e.u(qVar2, com.quizlet.ui.resources.designsystem.generated.j.h), function0, c0814p, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND, 0);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            AbstractC0382e.f(c0814p, new androidx.compose.foundation.layout.N(C0380d.e(c0814p).c));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(qVar2, z0Var, function0, i);
        }
    }

    public static final void c(com.quizlet.features.flashcards.data.q state, androidx.compose.ui.n nVar, com.quizlet.features.flashcards.screens.a aVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.flashcards.screens.a aVar2;
        int i2;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.n nVar3;
        com.quizlet.features.flashcards.screens.a aVar3;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1959348414);
        int i3 = i | (c0814p.h(state) ? 4 : 2) | 176 | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.h(function03) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            aVar3 = aVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
                c0814p.X(-1113093233);
                Object objB = K6.b(com.quizlet.features.flashcards.screens.a.class, ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getApplicationContext());
                c0814p.p(false);
                aVar2 = (com.quizlet.features.flashcards.screens.a) objB;
                i2 = i3 & (-897);
                nVar2 = nVar4;
            } else {
                c0814p.Q();
                aVar2 = aVar;
                i2 = i3 & (-897);
                nVar2 = nVar;
            }
            c0814p.q();
            e(function03, c0814p, (i2 >> 15) & 14);
            f(((com.quizlet.quizletandroid.u) aVar2).i1(), state.j, c0814p, 0);
            int i4 = i2 & 126;
            int i5 = i2 >> 3;
            a(state, nVar2, function0, function02, c0814p, (i5 & 7168) | i4 | (i5 & 896));
            nVar3 = nVar2;
            aVar3 = aVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) state, (Object) nVar3, (Object) aVar3, (Object) function0, (Object) function02, (Object) function03, i, 1);
        }
    }

    public static final long d(int i) {
        if (i > 0) {
            return i;
        }
        throw new IllegalArgumentException("The span value should be higher than 0");
    }

    public static final void e(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2116699744);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            c0814p.X(-1799080890);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                c0814p.i0(function0);
                objI = function0;
            }
            Function0 function02 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(-1799078444);
            boolean zH = c0814p.h(j);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new androidx.lifecycle.u0(20, j, function02);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.d(j, (Function1) objI2, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 0, function0);
        }
    }

    public static final void f(com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar, com.google.android.gms.internal.ads.N n, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.infra.ui.feedback.sound.soundeffect.b bVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1676899709);
        if ((((c0814p.h(eVar) ? 4 : 2) | i | (c0814p.h(n) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            if (n instanceof com.quizlet.features.flashcards.data.d) {
                bVar = com.quizlet.features.infra.ui.feedback.sound.soundeffect.b.c;
            } else if (n instanceof com.quizlet.features.flashcards.data.s) {
                bVar = com.quizlet.features.infra.ui.feedback.sound.soundeffect.b.b;
            } else {
                if (!(n instanceof com.quizlet.features.flashcards.data.u)) {
                    throw new NoWhenBranchMatchedException();
                }
                bVar = null;
            }
            c0814p.X(-1229928121);
            boolean zH = c0814p.h(j) | c0814p.f(bVar) | c0814p.h(eVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.lifecycle.compose.d(j, bVar, eVar, 8);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.d(j, (Function1) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(eVar, n, i, 12);
        }
    }
}
