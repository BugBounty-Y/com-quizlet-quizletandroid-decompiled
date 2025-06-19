package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.Q4;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.AbstractCollection;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4930v;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.x1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3409x1 {
    public static final void a(com.quizlet.features.onboarding.ell.v vVar, Function1 function1, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        com.quizlet.features.onboarding.ell.v vVar2 = vVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-877749625);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(vVar2) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, gVar, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            C0776c.E(c0814p, qVarC2, c0912h4);
            mVar.u();
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g), gVar, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            String strD = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_exam_selection_question);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(strD, qVarC4, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 48, 0, 65528);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.onboarding_ell_exam_selection_explanation), androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 48, 0, 65528);
            c0814p.p(true);
            mVar.s();
            androidx.compose.foundation.layout.B bA3 = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), gVar, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, nVar3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA3, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0776c.E(c0814p, qVarC5, c0912h4);
            int i7 = i3 & ContentType.LONG_FORM_ON_DEMAND;
            c(vVar, function1, c0814p, i3 & 126);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_exam_selection_another_reason);
            androidx.compose.ui.q qVarC6 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            c0814p.X(805762554);
            boolean z = i7 == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(21, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            vVar2 = vVar;
            Y4.b(strD2, qVarC6, (Function0) objI, false, null, null, 0L, 0L, null, null, null, c0814p, 48, 0, 4088);
            c0814p = c0814p;
            String strD3 = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_exam_selection_complete_profile);
            boolean z2 = !vVar2.a.isEmpty();
            androidx.compose.ui.q qVarC7 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            c0814p.X(805772064);
            boolean z3 = i7 == 32;
            Object objI2 = c0814p.I();
            if (z3 || objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(22, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            W4.a(strD3, qVarC7, (Function0) objI2, z2, null, null, null, null, null, false, c0814p, 48, 1008);
            c0814p.p(true);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 20, vVar2, function1, nVar2);
        }
    }

    public static final void b(com.quizlet.features.onboarding.ell.v vVar, com.quizlet.features.onboarding.ell.m mVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        androidx.compose.ui.graphics.painter.b bVarP;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(252531779);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(vVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(mVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            boolean zContains = vVar.a.contains(mVar);
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            int iOrdinal = mVar.ordinal();
            if (iOrdinal == 0) {
                i3 = R.string.onboarding_ell_exam_ielts;
            } else if (iOrdinal == 1) {
                i3 = R.string.onboarding_ell_exam_toelf;
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i3 = R.string.onboarding_ell_exam_toeic;
            }
            String strD = AbstractC3106b5.d(c0814p2, i3);
            c0814p2.X(1453306285);
            if (zContains) {
                ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                bVarP = com.quizlet.ui.resources.icons.d.p(c0814p2);
            } else {
                bVarP = null;
            }
            androidx.compose.ui.graphics.painter.b bVar = bVarP;
            c0814p2.p(false);
            c0814p2.X(-2075959545);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            C4078c c4078c = new C4078c(((com.quizlet.themes.b) c0814p2.j(b)).A(), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), ((com.quizlet.themes.b) c0814p2.j(b)).A(), ((com.quizlet.themes.b) c0814p2.j(b)).b.b(), ((com.quizlet.themes.b) c0814p2.j(b)).t, 32);
            c0814p2.p(false);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            c0814p2.X(1453302147);
            boolean zG = ((i2 & 896) == 256) | c0814p2.g(zContains) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p2.I();
            if (zG || objI == C0804k.a) {
                objI = new com.braze.r(function1, zContains, mVar);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            Y4.a(strD, qVarC, (Function0) objI, false, zContains, null, null, c4078c.a, 0L, null, null, bVar, false, c0814p, 48, 0, 5992);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 21, vVar, mVar, function1);
        }
    }

    public static final void c(com.quizlet.features.onboarding.ell.v vVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-62304139);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(vVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            kotlin.enums.b bVar = com.quizlet.features.onboarding.ell.m.b;
            bVar.getClass();
            androidx.collection.Y y = new androidx.collection.Y(bVar, 5);
            while (y.hasNext()) {
                b(vVar, (com.quizlet.features.onboarding.ell.m) y.next(), function1, c0814p, (i2 & 14) | ((i2 << 3) & 896));
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(vVar, function1, i, 12);
        }
    }

    public static final void d(com.quizlet.features.onboarding.ell.x onboardingELLState, Function1 onOnboardingELLEvent, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onboardingELLState, "onboardingELLState");
        Intrinsics.checkNotNullParameter(onOnboardingELLEvent, "onOnboardingELLEvent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1220668609);
        int i2 = i | (c0814p.f(onboardingELLState) ? 4 : 2) | (c0814p.h(onOnboardingELLEvent) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarC, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.t();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.k, 5);
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarY, c0374a);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarB);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            if (onboardingELLState instanceof com.quizlet.features.onboarding.ell.w) {
                c0814p.X(689182817);
                e(onOnboardingELLEvent, null, c0814p, (i2 >> 3) & 14);
                c0814p.p(false);
            } else {
                if (!(onboardingELLState instanceof com.quizlet.features.onboarding.ell.v)) {
                    throw com.google.android.gms.measurement.internal.Z.j(689180242, c0814p, false);
                }
                c0814p.X(689187331);
                a((com.quizlet.features.onboarding.ell.v) onboardingELLState, onOnboardingELLEvent, null, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 1, onboardingELLState, onOnboardingELLEvent, nVar2);
        }
    }

    public static final void e(Function1 function1, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        Function1 function12 = function1;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1798541302);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(function12) ? 4 : 2);
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, gVar, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            C0776c.E(c0814p, qVarC2, c0912h4);
            mVar.u();
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g), gVar, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            String strD = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_study_english_title);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).j;
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            nVar2 = nVar3;
            Q4.b(strD, qVarC4, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 48, 0, 65528);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.onboarding_ell_study_english_question), androidx.compose.foundation.layout.K0.c(nVar2, 1.0f), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).e, c0814p, 48, 0, 65528);
            c0814p.p(true);
            mVar.i();
            androidx.compose.foundation.layout.B bA3 = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.h.f), gVar, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, nVar2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA3, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0776c.E(c0814p, qVarC5, c0912h4);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_study_english_first_option);
            androidx.compose.ui.q qVarC6 = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            c0814p.X(1475177356);
            int i7 = i3 & 14;
            boolean z = i7 == 4;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(23, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            W4.a(strD2, qVarC6, (Function0) objI, false, null, null, null, null, null, false, c0814p, 48, 1016);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.onboarding_ell_study_english_second_option);
            androidx.compose.ui.q qVarC7 = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            c0814p.X(1475186920);
            boolean z2 = i7 == 4;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(24, function1);
                c0814p.i0(objI2);
            }
            Function0 function0 = (Function0) objI2;
            c0814p.p(false);
            function12 = function1;
            Y4.b(strD3, qVarC7, function0, false, null, null, 0L, 0L, null, null, null, c0814p, 48, 0, 4088);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(function12, nVar2, i, 11);
        }
    }

    public static final InterfaceC0773a0 f(kotlinx.coroutines.flow.a0 a0Var, Object obj, androidx.lifecycle.C c, androidx.lifecycle.B b, CoroutineContext coroutineContext, InterfaceC0806l interfaceC0806l, int i) {
        Object[] objArr = {a0Var, c, b, coroutineContext};
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zH = ((((i & 7168) ^ 3072) > 2048 && c0814p.d(b.ordinal())) || (i & 3072) == 2048) | c0814p.h(c) | c0814p.h(coroutineContext) | c0814p.h(a0Var);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zH || objI == v) {
            androidx.lifecycle.compose.c cVar = new androidx.lifecycle.compose.c(c, b, coroutineContext, a0Var, null);
            c0814p.i0(cVar);
            objI = cVar;
        }
        Function2 function2 = (Function2) objI;
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = C0776c.z(obj);
            c0814p.i0(objI2);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI2;
        Object[] objArrCopyOf = Arrays.copyOf(objArr, 4);
        boolean zH2 = c0814p.h(function2);
        Object objI3 = c0814p.I();
        if (zH2 || objI3 == v) {
            objI3 = new androidx.compose.runtime.R0(function2, interfaceC0773a0, null);
            c0814p.i0(objI3);
        }
        C0776c.h(objArrCopyOf, (Function2) objI3, c0814p);
        return interfaceC0773a0;
    }

    public static final InterfaceC0773a0 g(kotlinx.coroutines.flow.q0 q0Var, InterfaceC0806l interfaceC0806l) {
        androidx.lifecycle.J j = (androidx.lifecycle.J) ((C0814p) interfaceC0806l).j(androidx.lifecycle.compose.g.a);
        return f(q0Var, q0Var.getValue(), j.getLifecycle(), androidx.lifecycle.B.d, kotlin.coroutines.n.a, interfaceC0806l, 0);
    }

    public static final kotlinx.collections.immutable.e h(Object... elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        return kotlinx.collections.immutable.implementations.immutableList.g.c.b(C4930v.c(elements));
    }

    public static final kotlinx.collections.immutable.b i(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        kotlinx.collections.immutable.b bVar = iterable instanceof kotlinx.collections.immutable.b ? (kotlinx.collections.immutable.b) iterable : null;
        return bVar == null ? k(iterable) : bVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final kotlinx.collections.immutable.c j(AbstractCollection elements) {
        Intrinsics.checkNotNullParameter(elements, "<this>");
        kotlinx.collections.immutable.c cVar = elements instanceof kotlinx.collections.immutable.c ? (kotlinx.collections.immutable.c) elements : null;
        if (cVar != null) {
            return cVar;
        }
        kotlinx.collections.immutable.h hVar = elements instanceof kotlinx.collections.immutable.h ? (kotlinx.collections.immutable.h) elements : null;
        kotlinx.collections.immutable.implementations.persistentOrderedSet.b bVarB = hVar != null ? ((kotlinx.collections.immutable.implementations.persistentOrderedSet.c) hVar).b() : null;
        if (bVarB != null) {
            return bVarB;
        }
        kotlinx.collections.immutable.implementations.persistentOrderedSet.b bVar = kotlinx.collections.immutable.implementations.persistentOrderedSet.b.e;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        bVar.getClass();
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements.isEmpty()) {
            return bVar;
        }
        kotlinx.collections.immutable.implementations.persistentOrderedSet.c cVar2 = new kotlinx.collections.immutable.implementations.persistentOrderedSet.c(bVar);
        cVar2.addAll(elements);
        return cVar2.b();
    }

    public static final kotlinx.collections.immutable.e k(Iterable elements) {
        Intrinsics.checkNotNullParameter(elements, "<this>");
        kotlinx.collections.immutable.e eVar = elements instanceof kotlinx.collections.immutable.e ? (kotlinx.collections.immutable.e) elements : null;
        if (eVar != null) {
            return eVar;
        }
        kotlinx.collections.immutable.d dVar = elements instanceof kotlinx.collections.immutable.d ? (kotlinx.collections.immutable.d) elements : null;
        kotlinx.collections.immutable.e eVarE = dVar != null ? ((kotlinx.collections.immutable.implementations.immutableList.d) dVar).e() : null;
        if (eVarE != null) {
            return eVarE;
        }
        kotlinx.collections.immutable.implementations.immutableList.g gVar = kotlinx.collections.immutable.implementations.immutableList.g.c;
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements instanceof Collection) {
            return gVar.b((Collection) elements);
        }
        kotlinx.collections.immutable.implementations.immutableList.d dVarE = gVar.e();
        kotlin.collections.G.u(dVarE, elements);
        return dVarE.e();
    }

    public static final kotlinx.collections.immutable.g l(LinkedHashMap m) {
        Intrinsics.checkNotNullParameter(m, "<this>");
        kotlinx.collections.immutable.implementations.persistentOrderedMap.c cVar = kotlinx.collections.immutable.implementations.persistentOrderedMap.c.e;
        Intrinsics.e(cVar, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap<K of kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap.Companion.emptyOf, V of kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap.Companion.emptyOf>");
        Intrinsics.checkNotNullParameter(m, "m");
        if (m.isEmpty()) {
            return cVar;
        }
        kotlinx.collections.immutable.implementations.persistentOrderedMap.d dVar = new kotlinx.collections.immutable.implementations.persistentOrderedMap.d(cVar);
        dVar.putAll(m);
        return dVar.build();
    }
}
