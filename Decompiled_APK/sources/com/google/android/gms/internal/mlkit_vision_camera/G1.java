package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
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
import androidx.navigation.AbstractC1297t;
import androidx.navigation.C1296s;
import androidx.navigation.compose.C1280m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC4972a;
import kotlinx.coroutines.DispatchException;

/* loaded from: classes2.dex */
public abstract class G1 {
    public static final void a(com.quizlet.features.onboarding.survey.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1482060090);
        int i2 = (c0814p.h(nVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.w();
            float f = com.quizlet.ui.resources.designsystem.generated.j.f;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarX = AbstractC0382e.x(qVarC, f2, f, f2, f2);
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarX, c0374a);
            String strD = AbstractC3106b5.d(c0814p, R.string.continue_res);
            nVar.getClass();
            W4.a(strD, qVarB, function0, nVar.b != com.quizlet.features.onboarding.survey.m.b, null, null, null, null, null, false, c0814p, (i2 << 3) & 896, 1008);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(nVar, function0, i, 22);
        }
    }

    public static final void b(com.quizlet.features.onboarding.survey.n nVar, Function1 function1, androidx.compose.foundation.layout.z0 z0Var, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1341721549);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(z0Var) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.ui.n.b, z0Var);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c(AbstractC0382e.w(qVarT, f, DefinitionKt.NO_Float_VALUE, 2), 1.0f), AbstractC0460p.r(c0814p), false, 14);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1818377038);
            Iterator it2 = nVar.a.iterator();
            while (it2.hasNext()) {
                d((com.quizlet.features.onboarding.survey.m) it2.next(), nVar, function1, c0814p, (i2 << 3) & 1008);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 22, nVar, function1, z0Var);
        }
    }

    public static final void c(com.quizlet.features.onboarding.survey.n state, Function1 onSourceClicked, Function0 onContinue, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(onSourceClicked, "onSourceClicked");
        Intrinsics.checkNotNullParameter(onContinue, "onContinue");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1019144025);
        if (((i | (c0814p2.h(state) ? 4 : 2) | (c0814p2.h(onSourceClicked) ? 32 : 16) | (c0814p2.h(onContinue) ? 256 : 128) | 3072) & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.runtime.internal.d dVar = com.quizlet.features.onboarding.survey.b.a;
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-520015500, new androidx.navigation.compose.o(27, state, onContinue), c0814p2);
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(nVar2, dVar, dVarE, null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1188760982, new com.quizlet.assembly.compose.input.m(22, state, onSourceClicked), c0814p2), c0814p, 805306806, 248);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(state, onSourceClicked, onContinue, nVar2, i);
        }
    }

    public static final void d(com.quizlet.features.onboarding.survey.m mVar, com.quizlet.features.onboarding.survey.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long J;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(44897407);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(mVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(nVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-1556509895);
            Object objI = c0814p2.I();
            if (objI == C0804k.a) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(26, function1, mVar);
                c0814p2.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), "SourceComponent");
            String strD = AbstractC3106b5.d(c0814p2, mVar.a);
            c0814p2.X(-2075959545);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            C4078c c4078c = new C4078c(((com.quizlet.themes.b) c0814p2.j(b)).A(), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), ((com.quizlet.themes.b) c0814p2.j(b)).A(), ((com.quizlet.themes.b) c0814p2.j(b)).b.b(), ((com.quizlet.themes.b) c0814p2.j(b)).t, 32);
            c0814p2.p(false);
            C4093s c4093s = C4093s.a;
            float f = com.quizlet.themes.m.l;
            if (nVar.b == mVar) {
                c0814p2.X(-1006678795);
                J = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).J();
                c0814p2.p(false);
            } else {
                c0814p2.X(-1006600954);
                J = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).t;
                c0814p2.p(false);
            }
            c0814p = c0814p2;
            T4.a(strD, c4078c, qVarG, function0, false, c4093s, null, null, AbstractC0460p.a(J, f), null, null, c0814p, 3456, 0, 1744);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 23, mVar, nVar, function1);
        }
    }

    public static final void e(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-270574844);
        if (i == 0 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.s();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            androidx.compose.ui.q qVarX = AbstractC0382e.x(nVar, f3, f, f3, f2);
            c0814p2.X(-1784204838);
            C0416v0 c0416v0B = androidx.compose.material3.W4.b(c0814p2);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(c0416v0B, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            Q4.b(AbstractC3106b5.d(c0814p2, R.string.onboarding_survey_screen_title), androidx.compose.foundation.layout.U0.b(qVarX, c0374a), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).e, c0814p, 0, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 14);
        }
    }

    public static final void f(Throwable th, kotlin.coroutines.h hVar) throws Throwable {
        if (th instanceof DispatchException) {
            th = ((DispatchException) th).a;
        }
        kotlin.p pVar = kotlin.r.b;
        hVar.resumeWith(androidx.glance.appwidget.protobuf.Z.b(th));
        throw th;
    }

    public static C1296s g(androidx.lifecycle.B0 store) {
        Intrinsics.checkNotNullParameter(store, "viewModelStore");
        androidx.lifecycle.viewmodel.d factory = AbstractC1297t.a;
        androidx.lifecycle.viewmodel.a defaultCreationExtras = androidx.lifecycle.viewmodel.a.b;
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "extras");
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
        C4950i modelClass = kotlin.jvm.internal.K.a(C1296s.class);
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB != null) {
            return (C1296s) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
        }
        throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
    }

    public static final void h(kotlin.coroutines.h hVar, AbstractC4972a abstractC4972a) throws Throwable {
        try {
            kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(hVar);
            kotlin.p pVar = kotlin.r.b;
            kotlinx.coroutines.internal.b.g(Unit.a, hVarB);
        } catch (Throwable th) {
            f(th, abstractC4972a);
            throw null;
        }
    }

    public static final void i(Function2 function2, AbstractC4972a abstractC4972a, AbstractC4972a abstractC4972a2) {
        try {
            kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(kotlin.coroutines.intrinsics.h.a(abstractC4972a, abstractC4972a2, function2));
            kotlin.p pVar = kotlin.r.b;
            kotlinx.coroutines.internal.b.g(Unit.a, hVarB);
        } catch (Throwable th) {
            f(th, abstractC4972a2);
            throw null;
        }
    }
}
