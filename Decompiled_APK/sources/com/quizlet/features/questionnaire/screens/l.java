package com.quizlet.features.questionnaire.screens;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.S0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.q;
import androidx.lifecycle.C0;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.u;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.quizlet.features.folders.composables.C4256l;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r;
import com.quizlet.features.questionnaire.navigation.StepModel;
import com.quizlet.features.questionnaire.navigation.m;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public abstract class l {
    public static final void a(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(31249890);
        int i2 = (c0814p.f(bVar) ? 4 : 2) | i | (c0814p.h(hVar) ? 32 : 16) | (c0814p.h(aVar) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.features.questionnaire.navigation.i iVar = (com.quizlet.features.questionnaire.navigation.i) C0776c.m(((m) bVar).d, c0814p).getValue();
            c0814p.X(123963980);
            if (!(iVar instanceof com.quizlet.features.questionnaire.navigation.f)) {
                iVar = null;
            }
            com.quizlet.features.questionnaire.navigation.f fVar = (com.quizlet.features.questionnaire.navigation.f) iVar;
            if (fVar != null) {
                StepModel stepModel = fVar.a;
                if (!(stepModel instanceof StepModel.Exams)) {
                    stepModel = null;
                }
                StepModel.Exams exams = (StepModel.Exams) stepModel;
                if (exams != null) {
                    c0814p.X(320405677);
                    androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
                    eVar.b(com.quizlet.features.questionnaire.steps.h.a, new com.quizlet.features.questionnaire.steps.d(exams, aVar));
                    C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                    if (c0A == null) {
                        throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                    }
                    com.quizlet.features.questionnaire.steps.a aVar2 = (com.quizlet.features.questionnaire.steps.a) AbstractC3417z1.c(c0A, K.a(com.quizlet.features.questionnaire.steps.a.class), null, hVar, eVar);
                    c0814p.p(false);
                    b.a(aVar2, qVar, c0814p, (i2 >> 6) & ContentType.LONG_FORM_ON_DEMAND);
                }
            }
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new h(bVar, hVar, aVar, qVar, i, 0);
        }
    }

    public static final void b(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1902306646);
        if ((((c0814p.f(bVar) ? 4 : 2) | i | (c0814p.h(hVar) ? 32 : 16) | (c0814p.h(aVar) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.features.questionnaire.navigation.i iVar = (com.quizlet.features.questionnaire.navigation.i) C0776c.m(((m) bVar).d, c0814p).getValue();
            c0814p.X(123963980);
            if (!(iVar instanceof com.quizlet.features.questionnaire.navigation.f)) {
                iVar = null;
            }
            com.quizlet.features.questionnaire.navigation.f fVar = (com.quizlet.features.questionnaire.navigation.f) iVar;
            if (fVar != null) {
                StepModel stepModel = fVar.a;
                if (!(stepModel instanceof StepModel.Intro)) {
                    stepModel = null;
                }
                StepModel.Intro intro = (StepModel.Intro) stepModel;
                if (intro != null) {
                    c0814p.X(1454817965);
                    androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
                    eVar.b(com.quizlet.features.questionnaire.steps.h.a, new com.quizlet.features.questionnaire.steps.e(intro, aVar));
                    C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                    if (c0A == null) {
                        throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                    }
                    com.quizlet.features.questionnaire.steps.b bVar2 = (com.quizlet.features.questionnaire.steps.b) AbstractC3417z1.c(c0A, K.a(com.quizlet.features.questionnaire.steps.b.class), null, hVar, eVar);
                    c0814p.p(false);
                    com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                    mVar.s();
                    float f = com.quizlet.ui.resources.designsystem.generated.j.h;
                    mVar.u();
                    e.a(bVar2, AbstractC0382e.v(qVar, f, com.quizlet.ui.resources.designsystem.generated.j.g), c0814p, 0);
                }
            }
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new h(bVar, hVar, aVar, qVar, i, 1);
        }
    }

    public static final void c(H navController, com.quizlet.features.questionnaire.navigation.b viewModel, com.quizlet.features.questionnaire.steps.h viewModelFactory, com.quizlet.data.interactor.course.a navigationShim, q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(navController, "navController");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(viewModelFactory, "viewModelFactory");
        Intrinsics.checkNotNullParameter(navigationShim, "navigationShim");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1944295099);
        int i2 = i | (c0814p.h(navController) ? 4 : 2) | (c0814p.f(viewModel) ? 32 : 16) | (c0814p.h(viewModelFactory) ? 256 : 128) | (c0814p.h(navigationShim) ? 2048 : 1024) | (c0814p.f(qVar) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            V v = C0804k.a;
            c0814p.X(-50825941);
            boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p.h(viewModelFactory) | c0814p.h(navigationShim);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new androidx.lifecycle.compose.d(viewModel, viewModelFactory, navigationShim, 16);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Q1.d(navController, "questionnaire_intro", qVar, (Function1) objI, c0814p, ((i2 >> 6) & 896) | (i2 & 14) | 48, 8);
            d(viewModel, navController, function0, c0814p, ((i2 >> 3) & 14) | ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 9) & 896));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(navController, viewModel, viewModelFactory, navigationShim, qVar, function0, i);
        }
    }

    public static final void d(com.quizlet.features.questionnaire.navigation.b bVar, H h, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1117725003);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(bVar) : c0814p.h(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(h) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function0, c0814p);
            c0814p.X(-27409248);
            boolean zH = ((i2 & 14) == 4 || ((i2 & 8) != 0 && c0814p.h(bVar))) | c0814p.h(h) | c0814p.f(interfaceC0773a0D);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new j(bVar, h, interfaceC0773a0D, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.f(c0814p, bVar, (Function2) objI);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new u(i, 27, bVar, h, function0);
        }
    }

    public static final void e(com.quizlet.features.questionnaire.navigation.b viewModel, com.quizlet.features.questionnaire.steps.h stepsViewModelFactory, com.quizlet.data.interactor.course.a navigationShim, q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(stepsViewModelFactory, "stepsViewModelFactory");
        Intrinsics.checkNotNullParameter(navigationShim, "navigationShim");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(406916683);
        int i2 = i | (c0814p.f(viewModel) ? 4 : 2) | (c0814p.h(stepsViewModelFactory) ? 32 : 16) | (c0814p.h(navigationShim) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            H hD = O1.d(new W[0], c0814p);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1935880455, new k(viewModel, C0776c.m(((m) viewModel).e, c0814p), 1), c0814p);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(qVar, dVarE, null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(1575134428, new C4256l(hD, viewModel, stepsViewModelFactory, navigationShim, function0), c0814p), c0814p, ((i2 >> 9) & 14) | 805306416, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new r(viewModel, stepsViewModelFactory, navigationShim, qVar, function0, i);
        }
    }

    public static final void f(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(666688427);
        int i2 = (c0814p.f(bVar) ? 4 : 2) | i | (c0814p.h(hVar) ? 32 : 16) | (c0814p.h(aVar) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.features.questionnaire.navigation.i iVar = (com.quizlet.features.questionnaire.navigation.i) C0776c.m(((m) bVar).d, c0814p).getValue();
            c0814p.X(123963980);
            if (!(iVar instanceof com.quizlet.features.questionnaire.navigation.f)) {
                iVar = null;
            }
            com.quizlet.features.questionnaire.navigation.f fVar = (com.quizlet.features.questionnaire.navigation.f) iVar;
            if (fVar != null) {
                StepModel stepModel = fVar.a;
                if (!(stepModel instanceof StepModel.SchoolCourse)) {
                    stepModel = null;
                }
                StepModel.SchoolCourse schoolCourse = (StepModel.SchoolCourse) stepModel;
                if (schoolCourse != null) {
                    c0814p.X(2000734651);
                    androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
                    eVar.b(com.quizlet.features.questionnaire.steps.h.a, new com.quizlet.features.questionnaire.steps.f(schoolCourse, aVar));
                    C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                    if (c0A == null) {
                        throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                    }
                    com.quizlet.features.questionnaire.steps.c cVar = (com.quizlet.features.questionnaire.steps.c) AbstractC3417z1.c(c0A, K.a(com.quizlet.features.questionnaire.steps.c.class), null, hVar, eVar);
                    c0814p.p(false);
                    g.a(cVar, qVar, c0814p, (i2 >> 6) & ContentType.LONG_FORM_ON_DEMAND);
                }
            }
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new h(bVar, hVar, aVar, qVar, i, 2);
        }
    }
}
