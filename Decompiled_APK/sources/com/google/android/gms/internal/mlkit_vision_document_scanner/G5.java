package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
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
import com.google.android.gms.internal.mlkit_vision_document_scanner.G5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class G5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String text, androidx.compose.ui.q qVar, androidx.compose.ui.text.L l, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(821252147);
        int i2 = i | (c0814p2.f(text) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.f(l) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.q qVarA = C0418x.a.a(androidx.compose.ui.n.b, androidx.compose.ui.b.e);
            com.quizlet.themes.m.g.q();
            androidx.compose.material3.Q4.b(text, AbstractC0382e.w(qVarA, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).s(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 2, false, 0, 0, null, l, c0814p2, i2 & 14, ((i2 << 12) & 3670016) | 48, 62968);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 7, text, qVar, l);
        }
    }

    public static final void b(com.quizlet.assembly.compose.menu.o item, androidx.compose.ui.q qVar, androidx.compose.ui.text.L l, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long jF;
        Intrinsics.checkNotNullParameter(item, "item");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-182689474);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(item) : c0814p.h(item) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(l) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            boolean z = item.e;
            Intrinsics.checkNotNullParameter(item, "<this>");
            com.quizlet.assembly.compose.menu.p pVar = com.quizlet.assembly.compose.menu.p.d;
            com.quizlet.assembly.compose.menu.p pVar2 = item.f;
            boolean z2 = pVar2 != pVar;
            c0814p.X(1595992034);
            if (z2) {
                c0814p.X(1487822883);
                jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e;
                c0814p.p(false);
            } else if (item.g) {
                c0814p.X(1487824617);
                jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a();
                c0814p.p(false);
            } else {
                c0814p.X(1487826257);
                jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                c0814p.p(false);
            }
            c0814p.X(1666281118);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jF2 = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            long jB = ((com.quizlet.themes.b) c0814p.j(b)).b.b();
            c0814p.p(false);
            if (jF == 16) {
                jF = jF2;
            }
            com.quizlet.assembly.compose.menu.j jVar = new com.quizlet.assembly.compose.menu.j(jF, jB);
            c0814p.p(false);
            Intrinsics.checkNotNullParameter(item, "<this>");
            androidx.compose.runtime.internal.d dVarD = d(e(item.c, pVar2 == com.quizlet.assembly.compose.menu.p.b, c0814p), c0814p);
            Intrinsics.checkNotNullParameter(item, "<this>");
            androidx.compose.runtime.internal.d dVarD2 = d(e(item.d, pVar2 == com.quizlet.assembly.compose.menu.p.c, c0814p), c0814p);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-1695384989, new androidx.navigation.compose.o(7, item, l), c0814p);
            c0814p.X(1285961766);
            boolean z3 = ((i2 & 7168) == 2048) | ((i2 & 14) == 4 || ((i2 & 8) != 0 && c0814p.h(item)));
            Object objI = c0814p.I();
            if (z3 || objI == v) {
                objI = new com.braze.triggers.managers.h(18, function1, item);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            H5.a(dVarE, (Function0) objI, qVar, dVarD, dVarD2, z, jVar, null, null, c0814p, ((i2 << 3) & 896) | 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(item, qVar, l, function1, i, 0);
        }
    }

    public static final void c(float f, final float f2, final androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, final int i) {
        final float f3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1854962278);
        int i2 = (c0814p.c(f) ? 4 : 2) | i | (c0814p.c(f2) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            f3 = f;
        } else {
            nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.d(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), f2), "AssemblyMenuShimmerItem");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(C0418x.a.a(nVar, androidx.compose.ui.b.e), 1.0f);
            com.quizlet.themes.m.g.q();
            f3 = f;
            E5.b(f3, AbstractC0382e.w(qVarC2, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2), null, c0814p, i2 & 14, 4);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(f3, f2, nVar, i) { // from class: com.quizlet.assembly.compose.menu.h
                public final /* synthetic */ float a;
                public final /* synthetic */ float b;
                public final /* synthetic */ androidx.compose.ui.n c;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    float f4 = this.b;
                    androidx.compose.ui.n nVar2 = this.c;
                    G5.c(this.a, f4, nVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final androidx.compose.runtime.internal.d d(androidx.compose.ui.graphics.painter.b bVar, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(125057046);
        androidx.compose.runtime.internal.d dVarE = bVar == null ? null : androidx.compose.runtime.internal.e.e(-1478156184, new com.quizlet.assembly.compose.input.j(bVar, 1), c0814p);
        c0814p.p(false);
        return dVarE;
    }

    public static final androidx.compose.ui.graphics.painter.b e(androidx.compose.ui.graphics.painter.b bVar, boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1927632715);
        if (z) {
            com.quizlet.themes.e.a(c0814p).a.getClass();
            bVar = com.quizlet.ui.resources.icons.d.p(c0814p);
        }
        c0814p.p(false);
        return bVar;
    }
}
