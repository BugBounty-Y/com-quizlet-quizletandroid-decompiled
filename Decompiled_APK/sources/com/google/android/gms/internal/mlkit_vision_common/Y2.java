package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import androidx.activity.compose.o;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.T7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_common.Y2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.settings.viewmodels.C4447e;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.FacebookAuthActivity;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y2 {
    public static final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1781439079);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            P5.a(AbstractC3106b5.d(c0814p, R.string.delete_account_confirmation_error), null, null, null, null, null, null, null, null, null, c0814p, 0, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 16);
        }
    }

    public static final void b(androidx.navigation.H h, com.quizlet.features.infra.logout.viewmodels.a aVar, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, com.quizlet.features.settings.viewmodels.o oVar, com.quizlet.features.settings.viewmodels.n nVar, com.quizlet.features.infra.google.e eVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.infra.google.e eVar2;
        com.quizlet.features.settings.viewmodels.n nVar2;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar2;
        com.quizlet.features.settings.viewmodels.o oVar2;
        com.quizlet.features.settings.viewmodels.o oVar3;
        Context context;
        InterfaceC0773a0 interfaceC0773a0;
        InterfaceC0773a0 interfaceC0773a02;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar3;
        InterfaceC0773a0 interfaceC0773a03;
        C0814p c0814p;
        com.quizlet.features.settings.viewmodels.o oVar4;
        Intent intent;
        com.quizlet.features.settings.viewmodels.n nVar3;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar4;
        com.quizlet.features.infra.google.e eVar3;
        com.quizlet.features.settings.viewmodels.o oVar5;
        com.quizlet.features.settings.viewmodels.n nVar4;
        androidx.navigation.H navHostController = h;
        com.quizlet.features.infra.logout.viewmodels.a logoutViewModel = aVar;
        Intrinsics.checkNotNullParameter(navHostController, "navHostController");
        Intrinsics.checkNotNullParameter(logoutViewModel, "logoutViewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1741694573);
        if (((i | (c0814p2.h(navHostController) ? 4 : 2) | (c0814p2.h(logoutViewModel) ? 32 : 16) | 74880) & 74899) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            hVar4 = hVar;
            oVar5 = oVar;
            nVar4 = nVar;
            eVar3 = eVar;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                c0814p2.X(1907377511);
                androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                Object objB = K6.b(com.quizlet.features.settings.di.a.class, c0814p2.j(x0));
                c0814p2.p(false);
                com.quizlet.quizletandroid.ui.navigationmanagers.h hVar5 = (com.quizlet.quizletandroid.ui.navigationmanagers.h) ((C4622e) ((com.quizlet.features.settings.di.a) objB)).A.get();
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.settings.viewmodels.u.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p2);
                c0814p2.p(false);
                c0814p2.p(false);
                com.quizlet.features.settings.viewmodels.o oVar6 = (com.quizlet.features.settings.viewmodels.o) objE;
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A2 = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A2 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC2 = AbstractC3405w1.c(c0A2, c0814p2);
                c0814p2.Y(1729797275);
                Object objE2 = AbstractC3417z1.e(com.quizlet.features.settings.viewmodels.k.class, c0A2, null, fVarC2, c0A2 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A2).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p2);
                c0814p2.p(false);
                c0814p2.p(false);
                c0814p2.X(1907377511);
                Object objB2 = K6.b(com.quizlet.features.settings.di.a.class, c0814p2.j(x0));
                c0814p2.p(false);
                eVar2 = (com.quizlet.features.infra.google.e) ((C4622e) ((com.quizlet.features.settings.di.a) objB2)).B.get();
                nVar2 = (com.quizlet.features.settings.viewmodels.n) objE2;
                hVar2 = hVar5;
                oVar2 = oVar6;
            } else {
                c0814p2.Q();
                hVar2 = hVar;
                oVar2 = oVar;
                nVar2 = nVar;
                eVar2 = eVar;
            }
            c0814p2.q();
            c0814p2.X(528022381);
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) objI;
            c0814p2.p(false);
            com.quizlet.features.settings.viewmodels.k kVar = (com.quizlet.features.settings.viewmodels.k) nVar2;
            kotlinx.coroutines.flow.d0 d0Var = kVar.d;
            c0814p2.X(528026271);
            Object objI2 = c0814p2.I();
            if (objI2 == obj) {
                objI2 = new com.quizlet.features.settings.composables.deleteaccount.h(interfaceC0773a04, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p2.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p2);
            Unit unit = Unit.a;
            c0814p2.X(1667431386);
            boolean zH = c0814p2.h(j) | c0814p2.h(d0Var) | c0814p2.f(b) | c0814p2.f(interfaceC0773a0D);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == obj) {
                objI3 = new com.quizlet.features.settings.composables.deleteaccount.e(interfaceC0773a0D, j, null, d0Var);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit, (Function2) objI3);
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(kVar.c, c0814p2);
            Object[] objArr = new Object[0];
            c0814p2.X(528031713);
            Object objI4 = c0814p2.I();
            if (objI4 == obj) {
                objI4 = new com.quizlet.features.settings.composables.changeusername.c(3);
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            Object objD = com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI4, c0814p2, 3072, 6);
            C0814p c0814p3 = c0814p2;
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) objD;
            Context context2 = (Context) c0814p3.j(AndroidCompositionLocals_androidKt.b);
            Object objI5 = c0814p3.I();
            if (objI5 == obj) {
                objI5 = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p3), c0814p3);
            }
            kotlinx.coroutines.C c = ((C0839z) objI5).a;
            c0814p3.X(528036442);
            Object objI6 = c0814p3.I();
            if (objI6 == obj) {
                objI6 = new com.quizlet.features.settings.composables.deleteaccount.a(c, eVar2, oVar2, context2, 0);
                oVar3 = oVar2;
                context = context2;
                c0814p3.i0(objI6);
            } else {
                oVar3 = oVar2;
                context = context2;
            }
            Function0 function0 = (Function0) objI6;
            c0814p3.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = ((C4447e) oVar3).c;
            c0814p3.X(528048777);
            boolean zH2 = c0814p3.h(context);
            Object objI7 = c0814p3.I();
            if (zH2 || objI7 == obj) {
                objI7 = new com.quizlet.features.settings.composables.deleteaccount.i(context, null);
                c0814p3.i0(objI7);
            }
            c0814p3.p(false);
            c0814p3.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p3.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI7, c0814p3);
            c0814p3.X(1667431386);
            boolean zH3 = c0814p3.h(j2) | c0814p3.h(d0Var2) | c0814p3.f(b) | c0814p3.f(interfaceC0773a0D2);
            Object objI8 = c0814p3.I();
            if (zH3 || objI8 == obj) {
                interfaceC0773a0 = interfaceC0773a04;
                objI8 = new com.quizlet.features.settings.composables.deleteaccount.g(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p3.i0(objI8);
            } else {
                interfaceC0773a0 = interfaceC0773a04;
            }
            c0814p3.p(false);
            C0776c.f(c0814p3, unit, (Function2) objI8);
            c0814p3.p(false);
            androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
            c0814p3.X(528055329);
            boolean zH4 = c0814p3.h(context) | c0814p3.h(oVar3);
            Object objI9 = c0814p3.I();
            if (zH4 || objI9 == obj) {
                objI9 = new com.quizlet.features.settings.composables.deleteaccount.b(context, oVar3, 0);
                c0814p3.i0(objI9);
            }
            c0814p3.p(false);
            androidx.activity.compose.o oVarF = androidx.work.P.f(bVar, (Function1) objI9, c0814p3);
            com.quizlet.features.settings.viewmodels.u uVar = (com.quizlet.features.settings.viewmodels.u) oVar3;
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(uVar.e, c0814p3);
            c0814p3.X(528061580);
            Object objI10 = c0814p3.I();
            if (objI10 == obj) {
                objI10 = C0776c.z(null);
                c0814p3.i0(objI10);
            }
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) objI10;
            Object objG = com.google.android.gms.measurement.internal.Z.g(528063629, c0814p3, false);
            if (objG == obj) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p3.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a07 = (InterfaceC0773a0) objG;
            c0814p3.p(false);
            com.quizlet.features.settings.data.states.x xVar = (com.quizlet.features.settings.data.states.x) interfaceC0773a0M2.getValue();
            if (xVar instanceof com.quizlet.features.settings.data.states.u) {
                interfaceC0773a07.setValue(Boolean.FALSE);
                interfaceC0773a06.setValue(null);
            } else if (Intrinsics.b(xVar, com.quizlet.features.settings.data.states.v.a)) {
                interfaceC0773a07.setValue(Boolean.TRUE);
                interfaceC0773a06.setValue(null);
            } else if (xVar instanceof com.quizlet.features.settings.data.states.t) {
                interfaceC0773a07.setValue(Boolean.FALSE);
                interfaceC0773a06.setValue(((com.quizlet.features.settings.data.states.t) xVar).a);
            } else {
                if (!(xVar instanceof com.quizlet.features.settings.data.states.w)) {
                    throw new NoWhenBranchMatchedException();
                }
                uVar.f = null;
                uVar.D();
                while (true) {
                    kotlinx.coroutines.flow.s0 s0Var = kVar.c;
                    Object value = s0Var.getValue();
                    if (s0Var.k(value, com.quizlet.features.settings.data.states.m.a)) {
                        break;
                    }
                    navHostController = h;
                    logoutViewModel = aVar;
                    c0814p3 = c0814p3;
                }
            }
            com.quizlet.features.settings.data.states.s sVar = (com.quizlet.features.settings.data.states.s) interfaceC0773a0M.getValue();
            hVar2.getClass();
            Intent intent2 = new Intent(hVar2.a, (Class<?>) FacebookAuthActivity.class);
            c0814p3.X(528086632);
            boolean zH5 = c0814p3.h(navHostController);
            Object objI11 = c0814p3.I();
            if (zH5 || objI11 == obj) {
                interfaceC0773a02 = interfaceC0773a05;
                hVar3 = hVar2;
                interfaceC0773a03 = interfaceC0773a07;
                c0814p = c0814p3;
                oVar4 = oVar3;
                intent = intent2;
                com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, h, androidx.navigation.H.class, "navigateUp", "navigateUp()Z", 8, 8);
                c0814p.i0(cVar);
                objI11 = cVar;
            } else {
                interfaceC0773a02 = interfaceC0773a05;
                intent = intent2;
                hVar3 = hVar2;
                interfaceC0773a03 = interfaceC0773a07;
                c0814p = c0814p3;
                oVar4 = oVar3;
            }
            Function0 function02 = (Function0) objI11;
            c0814p.p(false);
            String str = (String) interfaceC0773a02.getValue();
            com.quizlet.qutils.string.g gVar = (com.quizlet.qutils.string.g) interfaceC0773a06.getValue();
            boolean zBooleanValue = ((Boolean) interfaceC0773a03.getValue()).booleanValue();
            c0814p.X(528101869);
            boolean zH6 = c0814p.h(logoutViewModel);
            Object objI12 = c0814p.I();
            if (zH6 || objI12 == obj) {
                com.quizlet.features.flashcards.navigation.c cVar2 = new com.quizlet.features.flashcards.navigation.c(0, logoutViewModel, com.quizlet.features.infra.logout.viewmodels.a.class, "onLogOutConfirmed", "onLogOutConfirmed(Lcom/quizlet/data/model/LogoutWarning;)V", 0, 9);
                c0814p.i0(cVar2);
                objI12 = cVar2;
            }
            Function0 function03 = (Function0) objI12;
            c0814p.p(false);
            c0814p.X(528104089);
            boolean zH7 = c0814p.h(nVar2);
            Object objI13 = c0814p.I();
            if (zH7 || objI13 == obj) {
                nVar3 = nVar2;
                objI13 = new com.quizlet.features.setpage.header.ui.a(0, nVar3, com.quizlet.features.settings.viewmodels.n.class, "onDeleteAccountClicked", "onDeleteAccountClicked()V", 0, 22);
                c0814p.i0(objI13);
            } else {
                nVar3 = nVar2;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI13;
            c0814p.p(false);
            c0814p.X(528095801);
            InterfaceC0773a0 interfaceC0773a08 = interfaceC0773a02;
            boolean zH8 = c0814p.h(oVar4) | c0814p.f(interfaceC0773a08);
            Object objI14 = c0814p.I();
            if (zH8 || objI14 == obj) {
                objI14 = new com.quizlet.features.questionnaire.screens.c(12, oVar4, interfaceC0773a08);
                c0814p.i0(objI14);
            }
            Function0 function04 = (Function0) objI14;
            boolean zR = AbstractC4178x.r(c0814p, false, 528099191, interfaceC0773a08);
            Object objI15 = c0814p.I();
            if (zR || objI15 == obj) {
                objI15 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a08, 20);
                c0814p.i0(objI15);
            }
            c0814p.p(false);
            com.quizlet.features.settings.viewmodels.o oVar7 = oVar4;
            C0814p c0814p4 = c0814p;
            com.quizlet.quizletandroid.ui.navigationmanagers.h hVar6 = hVar3;
            c(sVar, function0, oVarF, intent, gVar, zBooleanValue, str, function02, function04, (Function1) objI15, function03, (Function0) fVar, c0814p4, 560);
            c0814p2 = c0814p4;
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                a(c0814p2, 0);
            }
            hVar4 = hVar6;
            eVar3 = eVar2;
            oVar5 = oVar7;
            nVar4 = nVar3;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(h, aVar, hVar4, oVar5, nVar4, eVar3, i, 10);
        }
    }

    public static final void c(final com.quizlet.features.settings.data.states.s sVar, final Function0 function0, final androidx.activity.compose.o oVar, final Intent intent, final com.quizlet.qutils.string.g gVar, final boolean z, final String str, final Function0 function02, final Function0 function03, final Function1 function1, final Function0 function04, final Function0 function05, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(463608167);
        int i2 = i | (c0814p2.f(sVar) ? 4 : 2) | (c0814p2.h(oVar) ? 256 : 128) | (c0814p2.h(intent) ? 2048 : 1024) | (c0814p2.h(gVar) ? 16384 : 8192) | (c0814p2.g(z) ? 131072 : 65536) | (c0814p2.f(str) ? 1048576 : 524288) | (c0814p2.h(function02) ? 8388608 : 4194304) | (c0814p2.h(function03) ? 67108864 : 33554432) | (c0814p2.h(function1) ? 536870912 : 268435456);
        int i3 = (c0814p2.h(function04) ? (char) 4 : (char) 2) | (c0814p2.h(function05) ? ' ' : (char) 16);
        if ((i2 & 306783379) == 306783378 && (i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(-791538389, new com.quizlet.assembly.compose.menu.l(sVar, function02, function03, 23), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1367067850, new com.quizlet.features.settings.composables.deleteaccount.k(sVar, function05, gVar, str, z, function03, function0, oVar, intent, function1, function04), c0814p2), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(function0, oVar, intent, gVar, z, str, function02, function03, function1, function04, function05, i) { // from class: com.quizlet.features.settings.composables.deleteaccount.c
                public final /* synthetic */ Function0 b;
                public final /* synthetic */ o c;
                public final /* synthetic */ Intent d;
                public final /* synthetic */ com.quizlet.qutils.string.g e;
                public final /* synthetic */ boolean f;
                public final /* synthetic */ String g;
                public final /* synthetic */ Function0 h;
                public final /* synthetic */ Function0 i;
                public final /* synthetic */ Function1 j;
                public final /* synthetic */ Function0 k;
                public final /* synthetic */ Function0 l;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(561);
                    Intent intent2 = this.d;
                    Function0 function06 = this.k;
                    Function0 function07 = this.l;
                    Y2.c(this.a, this.b, this.c, intent2, this.e, this.f, this.g, this.h, this.i, this.j, function06, function07, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static void d(Context context) {
        boolean z;
        Object obj = com.google.android.gms.ads.internal.util.client.f.b;
        if (((Boolean) T7.a.o()).booleanValue()) {
            try {
                if (Settings.Global.getInt(context.getContentResolver(), "development_settings_enabled", 0) != 0) {
                    synchronized (com.google.android.gms.ads.internal.util.client.f.b) {
                        z = com.google.android.gms.ads.internal.util.client.f.c;
                    }
                    if (z) {
                        return;
                    }
                    com.google.common.util.concurrent.e eVarR = new com.google.android.gms.ads.internal.overlay.g(context).R();
                    com.google.android.gms.ads.internal.util.client.i.g("Updating ad debug logging enablement.");
                    AbstractC1972di.f(eVarR, "AdDebugLogUpdater.updateEnablement");
                }
            } catch (Exception e) {
                com.google.android.gms.ads.internal.util.client.i.i("Fail to determine debug setting.", e);
            }
        }
    }
}
