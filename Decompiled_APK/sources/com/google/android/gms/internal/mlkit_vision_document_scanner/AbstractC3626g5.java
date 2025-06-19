package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.lazy.grid.C0426a;
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
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.g5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3626g5 {
    public static final void a(kotlinx.collections.immutable.b bVar, Function1 function1, Function1 function12, Function1 function13, Function1 function14, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function15;
        Function1 function16;
        Function1 function17;
        androidx.compose.foundation.lazy.grid.A a;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1499448042);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function15 = function1;
            i2 |= c0814p2.h(function15) ? 32 : 16;
        } else {
            function15 = function1;
        }
        if ((i & 384) == 0) {
            function16 = function12;
            i2 |= c0814p2.h(function16) ? 256 : 128;
        } else {
            function16 = function12;
        }
        if ((i & 3072) == 0) {
            function17 = function13;
            i2 |= c0814p2.h(function17) ? 2048 : 1024;
        } else {
            function17 = function13;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function14) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            int iD = AbstractC3706q5.d(AbstractC3205m5.g(c0814p2).a);
            androidx.compose.foundation.lazy.grid.A a2 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            C0426a c0426a = new C0426a(iD);
            androidx.compose.foundation.layout.A0 a0C = AbstractC3706q5.c(true, c0814p2);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            c0814p2.X(-1670403917);
            boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 57344) == 16384) | c0814p2.h(bVar) | c0814p2.f(a2) | ((i2 & 896) == 256) | ((i2 & 7168) == 2048);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                com.quizlet.features.notes.detail.composables.magicnotesdetail.t tVar = new com.quizlet.features.notes.detail.composables.magicnotesdetail.t(bVar, a2, function14, function15, function16, function17, 2);
                a = a2;
                c0814p2.i0(tVar);
                objI = tVar;
            } else {
                a = a2;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3155h0.b(c0426a, fillElement, a, a0C, null, null, null, false, (Function1) objI, c0814p, 48, 496);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p((Object) bVar, function1, (Object) function12, (InterfaceC4938g) function13, (Object) function14, i, 18);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1246144829);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = i2 << 3;
            W4.a(AbstractC3106b5.d(c0814p, R.string.continue_with_google), qVar, function0, false, null, C4097w.a, null, com.quizlet.themes.e.a(c0814p).c.b(c0814p), null, false, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 196608 | (i3 & 896), 856);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(qVar, function0, i, 1);
        }
    }

    public static final void c(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1748871329);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c, AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(537590456);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(2131231285, c0814p, 0);
            c0814p.p(false);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.l();
            AbstractC0460p.c(bVarA, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            String strD = AbstractC3106b5.d(c0814p, R.string.library_empty_solutions);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).i;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            mVar.s();
            androidx.compose.material3.Q4.b(strD, androidx.compose.foundation.layout.K0.o(AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), com.quizlet.themes.m.x), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 22);
        }
    }

    public static final void d(Function1 function1, Function1 function12, Function1 function13, Function1 function14, com.quizlet.library.viewmodels.s sVar, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function15;
        Function1 function16;
        Function1 function17;
        Function1 function18;
        com.quizlet.library.viewmodels.s sVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1721803383);
        int i2 = (c0814p.h(function1) ? 4 : 2) | i | (c0814p.h(function12) ? 32 : 16) | (c0814p.h(function13) ? 256 : 128) | (c0814p.h(function14) ? 2048 : 1024) | 8192;
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            function15 = function1;
            function16 = function12;
            function17 = function13;
            function18 = function14;
            sVar2 = sVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.library.viewmodels.s.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                sVar = (com.quizlet.library.viewmodels.s) w0VarE;
            } else {
                c0814p.Q();
            }
            int i3 = i2 & (-57345);
            com.quizlet.library.viewmodels.s sVar3 = sVar;
            c0814p.q();
            com.quizlet.library.viewmodels.p pVar = (com.quizlet.library.viewmodels.p) AbstractC3409x1.g(sVar3.e, c0814p).getValue();
            if (pVar instanceof com.quizlet.library.viewmodels.m) {
                c0814p.X(753678551);
                function15 = function1;
                function16 = function12;
                function17 = function13;
                function18 = function14;
                a(((com.quizlet.library.viewmodels.m) pVar).a, function15, function16, function17, function18, c0814p, (i3 << 3) & 65520);
                c0814p.p(false);
            } else {
                function15 = function1;
                function16 = function12;
                function17 = function13;
                function18 = function14;
                if (pVar instanceof com.quizlet.library.viewmodels.n) {
                    c0814p.X(753688779);
                    c(c0814p, 0);
                    c0814p.p(false);
                } else {
                    if (!Intrinsics.b(pVar, com.quizlet.library.viewmodels.o.a)) {
                        throw com.google.android.gms.measurement.internal.Z.j(753676410, c0814p, false);
                    }
                    c0814p.X(753690726);
                    AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
                    c0814p.p(false);
                }
            }
            sVar2 = sVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(function15, function16, function17, function18, sVar2, i);
        }
    }
}
