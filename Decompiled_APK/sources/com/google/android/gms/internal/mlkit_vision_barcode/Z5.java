package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0775b0;
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
import com.comscore.streaming.ContentType;
import com.quizlet.features.folders.composables.C4257m;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.ExecutionException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes2.dex */
public abstract class Z5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String str, String str2, String str3, String str4, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(266260736);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(str2) ? 32 : 16) | (c0814p2.f(str3) ? 256 : 128) | (c0814p2.f(str4) ? 2048 : 1024) | (c0814p2.h(function0) ? 16384 : 8192) | (c0814p2.h(function02) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            function03 = function02;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.runtime.B b2 = com.quizlet.themes.l.a;
            float fB = ((com.quizlet.themes.j) c0814p2.j(b2)).B();
            float fA = ((com.quizlet.themes.j) c0814p2.j(b2)).A();
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.q();
            androidx.compose.ui.q qVarX = AbstractC0382e.x(qVarF, f, fB, f, fA);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f2), androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarX);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p2, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p2, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p2, qVarC, c0912h4);
            long jE = ((com.quizlet.themes.b) c0814p2.j(b)).b.e();
            androidx.compose.runtime.B b3 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(str, null, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b3)).e, c0814p2, i2 & 14, 0, 65530);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.s();
            int i4 = i2 >> 6;
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(str2, AbstractC0382e.w(qVarC2, DefinitionKt.NO_Float_VALUE, f2, 1), function0, false, null, null, null, null, null, false, c0814p2, ((i2 >> 3) & 14) | (i4 & 896), 1016);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.e, androidx.compose.ui.b.j, c0814p2, 6);
            int i5 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p2.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p2, qVarC3);
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, c0912h);
            C0776c.E(c0814p2, interfaceC0803j0L2, c0912h2);
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p2, i5, c0912h3);
            }
            C0776c.E(c0814p2, qVarC4, c0912h4);
            long jE2 = ((com.quizlet.themes.b) c0814p2.j(b)).b.e();
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b3)).o;
            androidx.compose.ui.text.font.u uVar = androidx.compose.ui.text.font.u.f;
            mVar.u();
            androidx.compose.material3.Q4.b(str3, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 11), jE2, 0L, uVar, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, (i4 & 14) | 196608, 0, 65496);
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).f0;
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p2.j(b3)).o;
            androidx.compose.ui.text.font.u uVar2 = androidx.compose.ui.text.font.u.h;
            c0814p2.X(804091529);
            boolean z = (i2 & 458752) == 131072;
            Object objI = c0814p2.I();
            if (z || objI == v) {
                function03 = function02;
                objI = new com.quizlet.features.setpage.composable.a(25, function03);
                c0814p2.i0(objI);
            } else {
                function03 = function02;
            }
            c0814p2.p(false);
            androidx.compose.material3.Q4.b(str4, AbstractC0460p.l(nVar, false, null, (Function0) objI, 7), j, 0L, uVar2, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p2, ((i2 >> 9) & 14) | 196608, 0, 65496);
            c0814p = c0814p2;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) str, (Object) str2, (Object) str3, (Object) str4, function0, function03, i, 17);
        }
    }

    public static final void b(com.quizlet.assembly.compose.modals.x state, String header, String signUpButtonText, String subheader, String loginButtonText, Function0 onSignUpButtonClick, Function0 onLogInButtonClick, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(signUpButtonText, "signUpButtonText");
        Intrinsics.checkNotNullParameter(subheader, "subheader");
        Intrinsics.checkNotNullParameter(loginButtonText, "loginButtonText");
        Intrinsics.checkNotNullParameter(onSignUpButtonClick, "onSignUpButtonClick");
        Intrinsics.checkNotNullParameter(onLogInButtonClick, "onLogInButtonClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(842103549);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(state) : c0814p2.h(state) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(header) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(signUpButtonText) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(subheader) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(loginButtonText) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(onSignUpButtonClick) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.h(onLogInButtonClick) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.f(nVar) ? 8388608 : 4194304;
        }
        int i3 = i2;
        if ((4793491 & i3) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(state, nVar, false, null, null, null, androidx.compose.runtime.internal.e.e(-199476318, new C4257m(header, signUpButtonText, subheader, loginButtonText, onSignUpButtonClick, onLogInButtonClick), c0814p2), c0814p, (i3 & 14) | 1572872 | ((i3 >> 18) & ContentType.LONG_FORM_ON_DEMAND), 60);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.e(state, header, signUpButtonText, subheader, loginButtonText, onSignUpButtonClick, onLogInButtonClick, i);
        }
    }

    public static final Object c(com.google.common.util.concurrent.e eVar, kotlin.coroutines.jvm.internal.c frame) {
        try {
            if (eVar.isDone()) {
                return androidx.concurrent.futures.h.h(eVar);
            }
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
            eVar.a(new androidx.camera.core.impl.utils.futures.h(eVar, c5028l), androidx.concurrent.futures.m.a);
            c5028l.u(new C0775b0(eVar, 28));
            Object objQ = c5028l.q();
            if (objQ == kotlin.coroutines.intrinsics.a.a) {
                Intrinsics.checkNotNullParameter(frame, "frame");
            }
            return objQ;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause == null) {
                Intrinsics.l();
            }
            throw cause;
        }
    }
}
