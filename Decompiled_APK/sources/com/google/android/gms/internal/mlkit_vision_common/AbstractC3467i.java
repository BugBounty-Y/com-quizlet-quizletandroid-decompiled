package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.material3.AbstractC0725t3;
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
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.features.folders.composables.C4256l;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3467i {
    public static final void a(int i) {
        if (i <= 0) {
            throw new IllegalArgumentException("px must be > 0.");
        }
    }

    public static final void b(androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1065441428);
        if ((i & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
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
            androidx.compose.animation.d0.w(6, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.written.ui.g(dVar, i, 0);
        }
    }

    public static final void c(com.quizlet.features.questiontypes.written.data.f fVar, Function2 function2, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1490474655);
        int i2 = i | (c0814p.h(fVar) ? 32 : 16) | (c0814p.h(function2) ? 256 : 128) | (c0814p.h(cVar) ? 2048 : 1024);
        if ((i2 & 1169) == 1168 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
            Integer num = fVar.b;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (num == null) {
                c0814p.X(622885749);
                androidx.compose.ui.q qVarD = androidx.compose.foundation.layout.K0.d(nVar2, ((androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f)).y(l.a.b));
                com.quizlet.themes.m.g.n();
                AbstractC0382e.f(c0814p, AbstractC0382e.y(qVarD, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.o, 7));
                c0814p.p(false);
                nVar = nVar2;
            } else {
                c0814p.X(623161029);
                String strD = AbstractC3106b5.d(c0814p, fVar.b.intValue());
                long jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.n();
                float f = com.quizlet.ui.resources.designsystem.generated.j.o;
                mVar.s();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.s();
                nVar = nVar2;
                androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar2, f2, DefinitionKt.NO_Float_VALUE, f2, f, 2), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
                c0814p = c0814p;
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarG = AbstractC0460p.g(nVar, com.quizlet.themes.m.k, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.k(), androidx.compose.ui.graphics.F.a);
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
            c0814p.X(137818046);
            boolean z = (i2 & 896) == 256;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.questiontypes.written.ui.f(function2, 0);
                c0814p.i0(objI);
            }
            Function2 function22 = (Function2) objI;
            c0814p.p(false);
            c0814p.X(137821527);
            boolean z2 = (i2 & 7168) == 2048;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new androidx.navigation.serialization.i(cVar, 1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.assembly.compose.input.q qVar = com.quizlet.assembly.compose.input.q.a;
            AbstractC3461h.a(fVar.a, null, function22, (kotlin.jvm.functions.c) objI2, qVar, DefinitionKt.NO_Float_VALUE, AbstractC3745v5.m(qVar, c0814p), c0814p, 0);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            AbstractC0382e.f(c0814p, new androidx.compose.foundation.layout.N(C0380d.e(c0814p).c));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 10, fVar, function2, cVar);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r14v4 */
    /* JADX WARN: Type inference failed for: r14v5, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r14v7 */
    public static final void d(com.quizlet.features.questiontypes.written.q qVar, com.quizlet.features.questiontypes.basequestion.data.a aVar, com.quizlet.features.questiontypes.written.a aVar2, com.quizlet.features.questiontypes.basequestion.i iVar, androidx.compose.ui.q qVar2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Object aVar3;
        int i3;
        InterfaceC0773a0 interfaceC0773a0;
        com.quizlet.features.questiontypes.written.data.g gVar;
        Object obj;
        ?? r14;
        int i4;
        int i5;
        Function0 function0;
        C0814p c0814p;
        StudiableImage studiableImage;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1501260847);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(aVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(aVar2) : c0814p2.h(aVar2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= (i & 4096) == 0 ? c0814p2.f(iVar) : c0814p2.h(iVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(qVar2) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            com.quizlet.features.questiontypes.written.data.g gVar2 = qVar.a;
            c0814p2.X(393851139);
            Object objI = c0814p2.I();
            Object obj2 = C0804k.a;
            if (objI == obj2) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            c0814p2.p(false);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p2, 48, 5);
            c0814p2.X(393859315);
            Object objI2 = c0814p2.I();
            if (objI2 == obj2) {
                objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 14);
                c0814p2.i0(objI2);
            }
            Function1 function1 = (Function1) objI2;
            c0814p2.p(false);
            c0814p2.X(393860756);
            int i6 = i2 & 896;
            boolean z = i6 == 256 || ((i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 && c0814p2.h(aVar2));
            Object objI3 = c0814p2.I();
            if (z || objI3 == obj2) {
                objI3 = new com.quizlet.features.questiontypes.written.ui.e(aVar2, 0);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            com.google.android.gms.internal.mlkit_vision_camera.C2.a(qVar.c, aVar, function1, (Function0) objI3, c0814p2, (i2 & ContentType.LONG_FORM_ON_DEMAND) | 384);
            c0814p2.X(393864035);
            boolean z2 = i6 == 256 || ((i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 && c0814p2.h(aVar2));
            Object objI4 = c0814p2.I();
            if (z2 || objI4 == obj2) {
                i3 = i2;
                interfaceC0773a0 = interfaceC0773a02;
                gVar = gVar2;
                obj = obj2;
                r14 = 0;
                i4 = 256;
                i5 = i6;
                aVar3 = new com.quizlet.features.notes.paywall.a(0, aVar2, com.quizlet.features.questiontypes.written.a.class, "logQuestionStart", "logQuestionStart()V", 0, 21);
                c0814p2.i0(aVar3);
            } else {
                i3 = i2;
                gVar = gVar2;
                interfaceC0773a0 = interfaceC0773a02;
                obj = obj2;
                r14 = 0;
                i5 = i6;
                aVar3 = objI4;
                i4 = 256;
            }
            c0814p2.p(r14);
            Function0 function02 = (Function0) ((kotlin.reflect.f) aVar3);
            c0814p2.X(393865730);
            boolean z3 = (i5 == i4 || ((i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 && c0814p2.h(aVar2))) ? true : r14;
            Object objI5 = c0814p2.I();
            if (z3 || objI5 == obj) {
                function0 = function02;
                com.quizlet.features.notes.paywall.a aVar4 = new com.quizlet.features.notes.paywall.a(0, aVar2, com.quizlet.features.questiontypes.written.a.class, "logQuestionStop", "logQuestionStop()V", 0, 22);
                c0814p2.i0(aVar4);
                objI5 = aVar4;
            } else {
                function0 = function02;
            }
            c0814p2.p(r14);
            com.google.android.gms.internal.mlkit_vision_camera.J2.a(function0, (Function0) ((kotlin.reflect.f) objI5), c0814p2, r14);
            com.google.android.gms.internal.mlkit_vision_camera.K2.a(((com.quizlet.features.questiontypes.written.o) aVar2).w, iVar, c0814p2, (i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, r14);
            int i7 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar2);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p2, i7, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1483439994, new com.quizlet.features.practicetest.results.i(4, interfaceC0773a0, qVar), c0814p2);
            com.quizlet.features.questiontypes.written.data.g gVar3 = gVar;
            com.quizlet.features.questiontypes.data.b bVar = gVar3.b;
            com.quizlet.features.questiontypes.data.d dVar = gVar3.a;
            AbstractC0725t3.a(null, null, dVarE, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(182387268, new C4256l(qVar, aVar2, bVar, xVarH, dVar, 5), c0814p2), c0814p2, 805306752, 507);
            c0814p = c0814p2;
            Z5.c((dVar == null || (studiableImage = dVar.b) == null) ? null : studiableImage.a(), null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(qVar, aVar, aVar2, iVar, qVar2, i, 12);
        }
    }

    public static final void e(com.quizlet.features.questiontypes.basequestion.i questionViewModel, androidx.compose.ui.q qVar, com.quizlet.features.questiontypes.written.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.questiontypes.written.a aVar2;
        int i2;
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(227204715);
        int i3 = (c0814p.f(questionViewModel) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            aVar2 = aVar;
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
                Object objE = AbstractC3417z1.e(com.quizlet.features.questiontypes.written.o.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p = c0814p;
                c0814p.p(false);
                c0814p.p(false);
                aVar2 = (com.quizlet.features.questiontypes.written.a) objE;
                i2 = i3 & (-897);
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.features.questiontypes.written.o oVar = (com.quizlet.features.questiontypes.written.o) aVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(oVar.q, c0814p);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(oVar.u, c0814p);
            com.quizlet.features.questiontypes.written.r rVar = (com.quizlet.features.questiontypes.written.r) interfaceC0773a0M.getValue();
            if (rVar instanceof com.quizlet.features.questiontypes.written.p) {
                c0814p.X(-602743374);
                C0814p c0814p2 = c0814p;
                AbstractC3249r5.a(qVar, 0L, c0814p2, (i2 >> 3) & 14, 2);
                c0814p = c0814p2;
                c0814p.p(false);
            } else {
                if (!(rVar instanceof com.quizlet.features.questiontypes.written.q)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1404917977, c0814p, false);
                }
                c0814p.X(-602644205);
                com.quizlet.features.questiontypes.written.r rVar2 = (com.quizlet.features.questiontypes.written.r) interfaceC0773a0M.getValue();
                Intrinsics.e(rVar2, "null cannot be cast to non-null type com.quizlet.features.questiontypes.written.WrittenUiState.ViewState");
                d((com.quizlet.features.questiontypes.written.q) rVar2, (com.quizlet.features.questiontypes.basequestion.data.a) interfaceC0773a0M2.getValue(), aVar2, questionViewModel, qVar, c0814p, 64512 & (i2 << 9));
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 9, qVar, (Object) questionViewModel, (Object) aVar2);
        }
    }
}
