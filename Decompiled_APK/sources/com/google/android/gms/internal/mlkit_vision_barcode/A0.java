package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.vector.C0866e;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.graphics.vector.C0868g;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A0 {
    public static C0867f a;

    public static final void a(kotlinx.collections.immutable.b filterOptions, com.quizlet.features.folders.addtofolder.data.o selectedOption, boolean z, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(filterOptions, "filterOptions");
        Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1063132386);
        int i2 = i | (c0814p.f(filterOptions) ? 4 : 2) | (c0814p.f(selectedOption) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | 3072 | (c0814p.h(function1) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.animation.E.g(z, androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), androidx.compose.animation.V.c(null, 3), androidx.compose.animation.V.d(null, 3), null, androidx.compose.runtime.internal.e.e(855906630, new com.quizlet.assembly.compose.input.h(filterOptions, selectedOption, function1, 3), c0814p), c0814p, ((i2 >> 6) & 14) | 200064, 16);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(filterOptions, selectedOption, z, nVar2, function1, i);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(957702385);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strD = AbstractC3106b5.d(c0814p, R.string.view_all_results);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarC, com.quizlet.ui.resources.designsystem.generated.j.h);
            c0814p.X(-817052752);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.composable.a(21, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3586b5.a(strD, qVarU, (Function0) objI, false, null, null, null, null, null, c0814p, 0, 1016);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 6, function0);
        }
    }

    public static final void c(androidx.compose.foundation.layout.z0 z0Var, com.quizlet.search.data.h hVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(884147201);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(z0Var) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(hVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "suggestionsList");
            c0814p.X(1003924183);
            boolean zH = ((i2 & 896) == 256) | c0814p.h(hVar) | ((i2 & 7168) == 2048);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.lifecycle.compose.d(hVar, function1, function0, 27);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarG, null, z0Var, null, null, null, false, (Function1) objI, c0814p, ((i2 << 6) & 896) | 6, 250);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(z0Var, hVar, function1, function0, i, 12);
        }
    }

    public static final void d(androidx.compose.foundation.layout.z0 z0Var, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1174270537);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(z0Var) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.ui.n.b, z0Var);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarT);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            b(function0, c0814p, (i2 >> 3) & 14);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.A(z0Var, function0, i, 1);
        }
    }

    public static final void e(kotlinx.collections.immutable.b bVar, com.quizlet.features.folders.addtofolder.data.o oVar, Function1 function1, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-454387809);
        int i2 = i | (c0814p.f(bVar) ? 4 : 2) | (c0814p.f(oVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p);
            c0814p.X(-7608394);
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
            Iterator<E> it2 = bVar.iterator();
            while (it2.hasNext()) {
                com.quizlet.features.folders.addtofolder.data.o oVar2 = (com.quizlet.features.folders.addtofolder.data.o) it2.next();
                arrayList.add(new com.quizlet.assembly.compose.menu.o(oVar2, g(oVar2, c0814p), null, null, false, oVar2 == oVar ? com.quizlet.assembly.compose.menu.p.c : com.quizlet.assembly.compose.menu.p.d, false, 188));
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.M5.a(androidx.compose.runtime.internal.e.e(-1245128570, new com.quizlet.assembly.compose.menu.l(oVar, sVarB, arrayList, 5), c0814p), nVar2, sVarB, function1, null, null, c0814p, 54 | ((i2 << 3) & 7168), 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) bVar, (Object) oVar, (Object) function1, nVar2, i, 3);
        }
    }

    public static final void f(com.quizlet.search.data.i state, Function1 onSuggestionClick, Function0 onViewAllClick, androidx.compose.foundation.layout.z0 z0Var, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(onSuggestionClick, "onSuggestionClick");
        Intrinsics.checkNotNullParameter(onViewAllClick, "onViewAllClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1316331768);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(state) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onSuggestionClick) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onViewAllClick) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(z0Var) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else if (Intrinsics.b(state, com.quizlet.search.data.g.a)) {
            c0814p.X(-1122813635);
            d(z0Var, onViewAllClick, c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 9) & 14));
            c0814p.p(false);
        } else {
            if (!(state instanceof com.quizlet.search.data.h)) {
                throw com.google.android.gms.measurement.internal.Z.j(-1122815162, c0814p, false);
            }
            c0814p.X(-1122810766);
            int i3 = (i2 >> 9) & 14;
            int i4 = i2 << 3;
            c(z0Var, (com.quizlet.search.data.h) state, onSuggestionClick, onViewAllClick, c0814p, i3 | (i4 & 896) | (i4 & 7168));
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(state, onSuggestionClick, onViewAllClick, z0Var, i, 11);
        }
    }

    public static final String g(com.quizlet.features.folders.addtofolder.data.o oVar, InterfaceC0806l interfaceC0806l) {
        int i;
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-932824120);
        int iOrdinal = oVar.ordinal();
        if (iOrdinal == 0) {
            i = -2122426631;
            i2 = R.string.flashcard_sets;
        } else if (iOrdinal == 1) {
            i = -2122423273;
            i2 = R.string.study_guides;
        } else {
            if (iOrdinal != 2) {
                throw com.google.android.gms.measurement.internal.Z.j(-2122428430, c0814p, false);
            }
            i = -2122419845;
            i2 = R.string.expert_solutions;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static final C0867f h() {
        C0867f c0867f = a;
        if (c0867f != null) {
            return c0867f;
        }
        C0866e c0866e = new C0866e("Filled.FilterNone", 24.0f, 24.0f, 24.0f, 24.0f, 0L, 0, false, 96);
        kotlin.collections.K k = androidx.compose.ui.graphics.vector.I.a;
        androidx.compose.ui.graphics.X x = new androidx.compose.ui.graphics.X(C0861v.b);
        C0868g c0868g = new C0868g(0);
        c0868g.g(3.0f, 5.0f);
        c0868g.e(1.0f, 5.0f);
        c0868g.j(16.0f);
        c0868g.c(DefinitionKt.NO_Float_VALUE, 1.1f, 0.9f, 2.0f, 2.0f, 2.0f);
        c0868g.d(16.0f);
        c0868g.j(-2.0f);
        c0868g.e(3.0f, 21.0f);
        c0868g.e(3.0f, 5.0f);
        c0868g.b();
        c0868g.g(21.0f, 1.0f);
        c0868g.e(7.0f, 1.0f);
        c0868g.c(-1.1f, DefinitionKt.NO_Float_VALUE, -2.0f, 0.9f, -2.0f, 2.0f);
        c0868g.j(14.0f);
        c0868g.c(DefinitionKt.NO_Float_VALUE, 1.1f, 0.9f, 2.0f, 2.0f, 2.0f);
        c0868g.d(14.0f);
        c0868g.c(1.1f, DefinitionKt.NO_Float_VALUE, 2.0f, -0.9f, 2.0f, -2.0f);
        c0868g.e(23.0f, 3.0f);
        c0868g.c(DefinitionKt.NO_Float_VALUE, -1.1f, -0.9f, -2.0f, -2.0f, -2.0f);
        c0868g.b();
        c0868g.g(21.0f, 17.0f);
        c0868g.e(7.0f, 17.0f);
        c0868g.e(7.0f, 3.0f);
        c0868g.d(14.0f);
        c0868g.j(14.0f);
        c0868g.b();
        C0866e.a(c0866e, c0868g.a, x);
        C0867f c0867fB = c0866e.b();
        a = c0867fB;
        return c0867fB;
    }
}
