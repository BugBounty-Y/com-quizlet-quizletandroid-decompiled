package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import android.content.Context;
import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.platform.N;
import androidx.lifecycle.B;
import androidx.lifecycle.C0;
import androidx.lifecycle.E;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.navigation.compose.x;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import com.google.android.gms.internal.mlkit_vision_common.r;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4759a;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4760b;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;

/* loaded from: classes3.dex */
public abstract class m {
    public static final float a;

    static {
        com.quizlet.themes.m.g.s();
        a = com.quizlet.ui.resources.designsystem.generated.j.h;
    }

    public static final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1905835547);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3515q.a((com.airbnb.lottie.h) r.d(new com.airbnb.lottie.compose.o(R.raw.confetti), c0814p).getValue(), N.G(K0.c(androidx.compose.ui.n.b, 1.0f), "test_results_confetti_animation"), 0, null, C0888i.a, c0814p, 48, 1572864, 4128764);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new x(i, 25);
        }
    }

    public static final void b(G g, t tVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        G g2;
        t tVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-12538378);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(g) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(tVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            g2 = g;
            tVar2 = tVar;
        } else {
            J j = (J) c0814p.j(androidx.lifecycle.compose.g.a);
            E eH = p0.h(j);
            c0814p.X(1794662455);
            boolean zH = c0814p.h(g) | c0814p.h(eH) | c0814p.h(tVar) | c0814p.h(j);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                g2 = g;
                tVar2 = tVar;
                objI = new androidx.navigation.internal.e(j, g2, eH, tVar2, 8);
                c0814p.i0(objI);
            } else {
                g2 = g;
                tVar2 = tVar;
            }
            c0814p.p(false);
            C0776c.d(j, (Function1) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(g2, tVar2, i, 27);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00fd  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:93:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4759a r20, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I r21, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4760b r22, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H r23, boolean r24, androidx.compose.ui.q r25, kotlin.jvm.functions.Function1 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 336
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.c(com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.a, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.b, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H, boolean, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void d(G testViewModel, androidx.compose.ui.q qVar, t tVar, com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        t tVar2;
        int i3;
        int i4;
        com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar2;
        com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar3;
        t tVar3;
        int i5;
        Intrinsics.checkNotNullParameter(testViewModel, "testViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1217512038);
        int i6 = i2 | (c0814p.h(testViewModel) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | 9344;
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            tVar3 = tVar;
            eVar3 = eVar;
            i5 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                w0 w0VarE = AbstractC3417z1.e(t.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                c0814p.X(-1113093233);
                Object objB = K6.b(com.quizlet.quizletandroid.ui.studymodes.testmode.di.a.class, ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getApplicationContext());
                c0814p.p(false);
                com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVarI1 = ((u) ((com.quizlet.quizletandroid.ui.studymodes.testmode.di.a) objB)).i1();
                tVar2 = (t) w0VarE;
                i3 = AbstractC3205m5.g(c0814p).a;
                i4 = i6 & (-65409);
                eVar2 = eVarI1;
            } else {
                c0814p.Q();
                tVar2 = tVar;
                i3 = i;
                i4 = i6 & (-65409);
                eVar2 = eVar;
            }
            c0814p.q();
            b(testViewModel, tVar2, c0814p, i4 & 14);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            boolean z = true ^ (i3 == 0);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            ((J) c0814p.j(abstractC0809m0)).getLifecycle().a(eVar2);
            c0814p.X(-316125865);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            Y y = tVar2.m;
            c0814p.X(-316122996);
            boolean zG = c0814p.g(z) | c0814p.h(eVar2);
            Object objI2 = c0814p.I();
            if (zG || objI2 == v) {
                objI2 = new i(z, eVar2, interfaceC0773a0, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            J j = (J) c0814p.j(abstractC0809m0);
            B b = B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(y) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new k(interfaceC0773a0D, j, null, y);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(tVar2.f, c0814p);
            InterfaceC0773a0 interfaceC0773a0G2 = AbstractC3409x1.g(tVar2.g, c0814p);
            InterfaceC0773a0 interfaceC0773a0G3 = AbstractC3409x1.g(tVar2.i, c0814p);
            InterfaceC0773a0 interfaceC0773a0G4 = AbstractC3409x1.g(tVar2.h, c0814p);
            C4759a c4759a = (C4759a) interfaceC0773a0G.getValue();
            I i7 = (I) interfaceC0773a0G2.getValue();
            C4760b c4760b = (C4760b) interfaceC0773a0G3.getValue();
            H h = (H) interfaceC0773a0G4.getValue();
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            c0814p.X(-316093625);
            boolean zH = c0814p.h(tVar2);
            Object objI4 = c0814p.I();
            if (zH || objI4 == v) {
                objI4 = new y(1, tVar2, t.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/testmode/viewmodels/TestResultsEvent;)V", 0, 12);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            c(c4759a, i7, c4760b, h, zBooleanValue, qVar, (Function1) ((kotlin.reflect.f) objI4), c0814p, (i4 << 12) & 458752, 0);
            eVar3 = eVar2;
            tVar3 = tVar2;
            i5 = i3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(testViewModel, qVar, tVar3, eVar3, i5, i2);
        }
    }
}
