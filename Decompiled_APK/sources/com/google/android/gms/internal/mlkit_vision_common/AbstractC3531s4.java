package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0725t3;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.learn.data.C4536a;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.s4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3531s4 {
    public static final void a(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1671523525);
        int i2 = (c0814p.d(R.string.study_again) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.h(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m.g.q();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarF, com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
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
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(AbstractC3106b5.d(c0814p, R.string.study_again), androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.n(nVar, com.quizlet.themes.m.Q, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), "primaryCta"), function0, false, null, null, null, null, null, false, c0814p, (i2 << 3) & 896, 1016);
            c0814p = c0814p;
            function03 = function0;
            androidx.compose.material3.Z1.m(function02, null, false, null, null, null, com.quizlet.learn.ui.b.a, c0814p, ((i2 >> 6) & 14) | 805306368, 510);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function03, function02, i, 6);
        }
    }

    public static final void b(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1277323715);
        int i3 = i2 | (c0814p2.d(R.string.assistant_checkpoint_msg_percent_100_reaching_mastery) ? 4 : 2) | (c0814p2.d(i) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.f(qVar) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p2.j(b)).b.h(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarG = AbstractC0382e.u(qVarF, com.quizlet.ui.resources.designsystem.generated.j.i).g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p2, 54);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(str, null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, new androidx.compose.ui.text.L(0L, S5.g(48), null, null, null, 0L, 0, 0L, 16777213), c0814p2, (i3 >> 6) & 14, 1572864, 65534);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.K0.o(nVar, f));
            String strD = AbstractC3106b5.d(c0814p2, R.string.assistant_checkpoint_msg_percent_100_reaching_mastery);
            long jE = ((com.quizlet.themes.b) c0814p2.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, null, jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).d, c0814p2, 0, 0, 65018);
            mVar.s();
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.K0.o(nVar, f));
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, i), null, ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).p, c0814p2, 0, 0, 65018);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(i, str, qVar, i2);
        }
    }

    public static final void c(C4536a viewState, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        int i4;
        Function0 function03;
        Function0 function04;
        Function0 function05;
        Function0 function06;
        Intrinsics.checkNotNullParameter(viewState, "viewState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1155355534);
        int i5 = i | (c0814p.f(viewState) ? 4 : 2);
        int i6 = i2 & 2;
        if (i6 != 0) {
            i3 = i5 | 48;
        } else {
            i3 = i5 | (c0814p.h(function0) ? 32 : 16);
        }
        int i7 = i2 & 4;
        if (i7 != 0) {
            i4 = i3 | 384;
        } else {
            i4 = i3 | (c0814p.h(function02) ? 256 : 128);
        }
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function05 = function0;
            function06 = function02;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            if (i6 != 0) {
                c0814p.X(1394533684);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new com.quizlet.features.settings.composables.changeusername.c(16);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function03 = (Function0) objI;
            } else {
                function03 = function0;
            }
            if (i7 != 0) {
                c0814p.X(1394535028);
                Object objI2 = c0814p.I();
                if (objI2 == v) {
                    objI2 = new com.quizlet.features.settings.composables.changeusername.c(17);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                function04 = (Function0) objI2;
            } else {
                function04 = function02;
            }
            if (!(viewState instanceof C4536a)) {
                throw com.google.android.gms.measurement.internal.Z.j(1394535834, c0814p, false);
            }
            c0814p.X(1394539579);
            d(viewState.a, viewState.b, function03, function04, c0814p, (i4 << 9) & 516096);
            c0814p.p(false);
            function05 = function03;
            function06 = function04;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, i2, 14, (Object) viewState, (Object) function05, (InterfaceC4938g) function06);
        }
    }

    public static final void d(int i, String str, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2146640336);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.d(R.string.assistant_checkpoint_msg_percent_100_reaching_mastery) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.d(R.string.study_again) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.f(str) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p2.h(function02) ? 131072 : 65536;
        }
        if ((i3 & 74899) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            AbstractC0725t3.a(null, null, androidx.compose.runtime.internal.e.e(-1087000363, new com.quizlet.features.notes.upload.composables.upload.b(2, function0, function02), c0814p2), null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(1792944671, new com.quizlet.features.notes.modals.e(i, str, 1), c0814p2), c0814p, 805306752, 507);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i, i2, 8, (Object) str, (Object) function0, (InterfaceC4938g) function02);
        }
    }

    public static void e(int i, Object[] objArr) {
        for (int i2 = 0; i2 < i; i2++) {
            if (objArr[i2] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i2, "at index "));
            }
        }
    }
}
