package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import android.widget.Toast;
import androidx.activity.result.ActivityResult;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.features.settings.viewmodels.C4447e;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.h3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3465h3 {
    public static final void a(com.quizlet.features.settings.data.models.f fVar, com.quizlet.data.interactor.folderwithcreator.m mVar, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, androidx.activity.compose.o oVar, Function0 function0, com.quizlet.features.settings.viewmodels.o oVar2, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-842926766);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(fVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p2.f(mVar) : c0814p2.h(mVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(hVar) : c0814p2.h(hVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(oVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function0) ? 16384 : 8192;
        }
        if ((i & 196608) == 0) {
            i2 |= (262144 & i) == 0 ? c0814p2.f(oVar2) : c0814p2.h(oVar2) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.h(function2) ? 1048576 : 524288;
        }
        if ((599187 & i2) == 599186 && c0814p2.x()) {
            c0814p2.Q();
        } else {
            c0814p2.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(((com.quizlet.features.settings.viewmodels.u) oVar2).e, c0814p2);
            c0814p2.X(957627596);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = C0776c.z(null);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(957629964, c0814p2, false);
            if (objG == v) {
                objG = C0776c.z(null);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(957632013, c0814p2, false);
            if (objG2 == v) {
                objG2 = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objG2);
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objG2;
            Object objG3 = com.google.android.gms.measurement.internal.Z.g(957634193, c0814p2, false);
            if (objG3 == v) {
                objG3 = new com.quizlet.features.questionnaire.screens.c(13, mVar, oVar2);
                c0814p2.i0(objG3);
            }
            Function0 function02 = (Function0) objG3;
            c0814p2.p(false);
            com.quizlet.features.settings.data.states.x xVar = (com.quizlet.features.settings.data.states.x) interfaceC0773a0M.getValue();
            if (xVar instanceof com.quizlet.features.settings.data.states.u) {
                interfaceC0773a0.setValue(((com.quizlet.features.settings.data.states.u) xVar).a);
                interfaceC0773a03.setValue(Boolean.FALSE);
                interfaceC0773a02.setValue(null);
            } else if (Intrinsics.b(xVar, com.quizlet.features.settings.data.states.v.a)) {
                interfaceC0773a03.setValue(Boolean.TRUE);
                interfaceC0773a02.setValue(null);
            } else if (xVar instanceof com.quizlet.features.settings.data.states.t) {
                interfaceC0773a03.setValue(Boolean.FALSE);
                interfaceC0773a02.setValue(((com.quizlet.features.settings.data.states.t) xVar).a);
            } else {
                if (!(xVar instanceof com.quizlet.features.settings.data.states.w)) {
                    throw new NoWhenBranchMatchedException();
                }
                function02.invoke();
                com.quizlet.features.settings.data.states.w wVar = (com.quizlet.features.settings.data.states.w) xVar;
                function2.invoke(wVar.b, wVar.a);
            }
            int iOrdinal = fVar.ordinal();
            if (iOrdinal == 0) {
                c0814p2.X(957659421);
                com.quizlet.features.settings.data.models.b bVar = (com.quizlet.features.settings.data.models.b) interfaceC0773a0.getValue();
                c0814p2.X(957664618);
                boolean z = (i2 & 57344) == 16384;
                Object objI2 = c0814p2.I();
                if (z || objI2 == v) {
                    objI2 = new com.quizlet.features.setpage.composable.a(15, function0);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                com.google.android.gms.auth.api.b.a(bVar, (com.quizlet.assembly.compose.modals.x) mVar.d, (Function0) objI2, function02, c0814p2, 3136);
                c0814p2.p(false);
            } else if (iOrdinal == 1) {
                c0814p2.X(-377022801);
                com.quizlet.features.settings.data.models.b bVar2 = (com.quizlet.features.settings.data.models.b) interfaceC0773a0.getValue();
                boolean zBooleanValue = ((Boolean) interfaceC0773a03.getValue()).booleanValue();
                com.quizlet.qutils.string.g gVar = (com.quizlet.qutils.string.g) interfaceC0773a02.getValue();
                c0814p2.X(957676945);
                boolean z2 = (((458752 & i2) ^ 196608) > 131072 && c0814p2.h(oVar2)) || (i2 & 196608) == 131072;
                Object objI3 = c0814p2.I();
                if (z2 || objI3 == v) {
                    c0814p = c0814p2;
                    objI3 = new com.quizlet.features.settings.composables.x(1, oVar2, com.quizlet.features.settings.viewmodels.o.class, "onVerifyPassword", "onVerifyPassword(Ljava/lang/String;)V", 0, 7);
                    c0814p.i0(objI3);
                } else {
                    c0814p = c0814p2;
                }
                c0814p.p(false);
                C0814p c0814p3 = c0814p;
                AbstractC3459g3.a(bVar2, (com.quizlet.assembly.compose.modals.x) mVar.c, (Function1) ((kotlin.reflect.f) objI3), function02, zBooleanValue, gVar, c0814p3, 3136);
                c0814p2 = c0814p3;
                c0814p2.p(false);
            } else {
                if (iOrdinal != 2) {
                    throw com.google.android.gms.measurement.internal.Z.j(957658621, c0814p2, false);
                }
                c0814p2.X(957680842);
                com.quizlet.features.settings.data.models.b bVar3 = (com.quizlet.features.settings.data.models.b) interfaceC0773a0.getValue();
                c0814p2.X(957686163);
                boolean zH = c0814p2.h(oVar) | ((i2 & 896) == 256 || ((i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 && c0814p2.h(hVar)));
                Object objI4 = c0814p2.I();
                if (zH || objI4 == v) {
                    objI4 = new com.quizlet.features.questionnaire.screens.c(14, oVar, hVar);
                    c0814p2.i0(objI4);
                }
                c0814p2.p(false);
                AbstractC3441d3.a(bVar3, (com.quizlet.assembly.compose.modals.x) mVar.e, (Function0) objI4, function02, c0814p2, 3136);
                c0814p2.p(false);
                c0814p2 = c0814p2;
            }
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.e(fVar, mVar, hVar, oVar, function0, oVar2, function2, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void b(com.quizlet.features.settings.data.models.f reAuthType, com.quizlet.data.interactor.folderwithcreator.m modalStates, com.quizlet.features.infra.logout.composables.a logoutModalStates, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, com.quizlet.features.infra.google.e eVar, com.quizlet.features.settings.viewmodels.o oVar, Function2 function2, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        int i4;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar2;
        com.quizlet.features.infra.google.e eVar2;
        com.quizlet.features.infra.google.e eVar3;
        boolean z;
        Context context;
        C0814p c0814p;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar3;
        com.quizlet.features.infra.google.e eVar4;
        Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
        Intrinsics.checkNotNullParameter(modalStates, "modalStates");
        Intrinsics.checkNotNullParameter(logoutModalStates, "logoutModalStates");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-884246794);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(reAuthType) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p2.f(modalStates) : c0814p2.h(modalStates) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(logoutModalStates) : c0814p2.h(logoutModalStates) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= 8192;
        }
        if ((i & 196608) == 0) {
            i2 |= (262144 & i) == 0 ? c0814p2.f(oVar) : c0814p2.h(oVar) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.h(function2) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.h(function1) ? 8388608 : 4194304;
        }
        if ((4793491 & i2) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            hVar3 = hVar;
            eVar4 = eVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i5 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i5 == 0 || c0814p2.w()) {
                c0814p2.X(1907377511);
                androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                i3 = 196608;
                Object objB = K6.b(com.quizlet.features.settings.di.a.class, c0814p2.j(x0));
                c0814p2.p(false);
                com.quizlet.quizletandroid.ui.navigationmanagers.h hVar4 = (com.quizlet.quizletandroid.ui.navigationmanagers.h) ((C4622e) ((com.quizlet.features.settings.di.a) objB)).A.get();
                c0814p2.X(1907377511);
                Object objB2 = K6.b(com.quizlet.features.settings.di.a.class, c0814p2.j(x0));
                c0814p2.p(false);
                i4 = i2 & (-64513);
                hVar2 = hVar4;
                eVar2 = (com.quizlet.features.infra.google.e) ((C4622e) ((com.quizlet.features.settings.di.a) objB2)).B.get();
            } else {
                c0814p2.Q();
                i4 = i2 & (-64513);
                eVar2 = eVar;
                i3 = 196608;
                hVar2 = hVar;
            }
            int i6 = i4;
            c0814p2.q();
            Context context2 = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p2), c0814p2);
            }
            kotlinx.coroutines.C c = ((C0839z) objI).a;
            c0814p2.X(-1142820814);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                context = context2;
                z = false;
                com.quizlet.features.settings.composables.deleteaccount.a aVar = new com.quizlet.features.settings.composables.deleteaccount.a(c, eVar2, oVar, context, 1);
                eVar3 = eVar2;
                c0814p2.i0(aVar);
                objI2 = aVar;
            } else {
                eVar3 = eVar2;
                z = false;
                context = context2;
            }
            Function0 function0 = (Function0) objI2;
            c0814p2.p(z);
            kotlinx.coroutines.flow.d0 d0Var = ((C4447e) oVar).c;
            c0814p2.X(-1142808511);
            boolean zH = c0814p2.h(context);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == v) {
                objI3 = new com.quizlet.features.settings.composables.dialogs.h(context, null);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p2.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI3, c0814p2);
            Unit unit = Unit.a;
            c0814p2.X(1667431386);
            boolean zH2 = c0814p2.h(j) | c0814p2.h(d0Var) | c0814p2.f(b) | c0814p2.f(interfaceC0773a0D);
            Object objI4 = c0814p2.I();
            if (zH2 || objI4 == v) {
                objI4 = new com.quizlet.features.settings.composables.dialogs.g(interfaceC0773a0D, j, null, d0Var);
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit, (Function2) objI4);
            c0814p2.p(false);
            androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
            c0814p2.X(-1142801959);
            int i7 = i6 & 458752;
            boolean zH3 = c0814p2.h(context) | (((i7 ^ i3) > 131072 && c0814p2.h(oVar)) || (i6 & i3) == 131072);
            Object objI5 = c0814p2.I();
            if (zH3 || objI5 == v) {
                objI5 = new com.quizlet.features.settings.composables.deleteaccount.b(context, oVar, 1);
                c0814p2.i0(objI5);
            }
            c0814p2.p(false);
            androidx.activity.compose.o oVarF = androidx.work.P.f(bVar, (Function1) objI5, c0814p2);
            AbstractC3429b3.b((com.quizlet.assembly.compose.modals.x) modalStates.b, c0814p2, 8);
            c0814p = c0814p2;
            com.quizlet.quizletandroid.ui.navigationmanagers.h hVar5 = hVar2;
            a(reAuthType, modalStates, hVar5, oVarF, function0, oVar, function2, c0814p, (i6 & 14) | 24640 | (i6 & ContentType.LONG_FORM_ON_DEMAND) | 4096 | i7 | (i6 & 3670016));
            AbstractC3315z6.a(logoutModalStates, function1, null, c0814p, ((i6 >> 6) & 14) | 8 | ((i6 >> 18) & ContentType.LONG_FORM_ON_DEMAND), 4);
            hVar3 = hVar5;
            eVar4 = eVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.E(reAuthType, modalStates, logoutModalStates, hVar3, eVar4, oVar, function2, function1, i);
        }
    }

    public static void c(Status status, Object obj, com.google.android.gms.tasks.f fVar) {
        if (status.a()) {
            fVar.b(obj);
        } else {
            fVar.a(com.google.android.gms.common.internal.u.m(status));
        }
    }

    public static void d(Status status, Object obj, com.google.android.gms.tasks.f fVar) {
        if (status.a()) {
            fVar.a.q(obj);
        } else {
            fVar.c(com.google.android.gms.common.internal.u.m(status));
        }
    }

    public static final void e(ActivityResult activityResult, Context context, Function1 block) {
        Intrinsics.checkNotNullParameter(activityResult, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        Intent intent = activityResult.b;
        String stringExtra = intent != null ? intent.getStringExtra("com.quizlet.quizletandroid.EXTRA_ACCESS_TOKEN") : null;
        if (activityResult.a == -1 && stringExtra != null) {
            block.invoke(stringExtra);
        } else {
            Intrinsics.checkNotNullParameter(context, "context");
            Toast.makeText(context, R.string.client_error_net_exception, 0).show();
        }
    }
}
