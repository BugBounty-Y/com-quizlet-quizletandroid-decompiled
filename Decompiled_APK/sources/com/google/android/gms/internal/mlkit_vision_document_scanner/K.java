package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
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
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class K {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function0 function0) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1881172069);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarU = AbstractC0460p.u(qVar.g(androidx.compose.foundation.layout.K0.c), AbstractC0460p.r(c0814p2), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p2, 48);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarU);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.l();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k);
            com.quizlet.themes.e.a(c0814p2).d.getClass();
            c0814p2.X(604225846);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_email_confirmation, c0814p2, 0);
            c0814p2.p(false);
            AbstractC0460p.c(bVarA, null, qVarK, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p2, 48, 120);
            float f = com.quizlet.themes.m.B0;
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, f, 1);
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarQ, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            String strC = AbstractC3106b5.c(R.string.confirm_email_sent_title, new Object[]{str}, c0814p2);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b)).e;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strC, qVarY, ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65016);
            androidx.compose.ui.q qVarQ2 = androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, f, 1);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.confirm_email_sent_message), AbstractC0382e.y(qVarQ2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b)).o, c0814p2, 0, 0, 65016);
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.A0, 1), 1.0f);
            mVar.q();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarC2, f2, DefinitionKt.NO_Float_VALUE, 2);
            mVar.p();
            W4.a(AbstractC3106b5.d(c0814p2, R.string.go_back_to_login_button_text), AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 7), function0, false, null, null, null, null, null, false, c0814p2, i2 & 896, 1016);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.emailsent.ui.a(qVar, str, function0, i, 1);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String email, Function0 function0) {
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(email, "email");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(74597900);
        int i2 = i | (c0814p2.f(email) ? 4 : 2) | 48 | (c0814p2.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(-212673266);
            boolean z = (i2 & 896) == 256;
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(16, function0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            androidx.work.impl.t.a(false, (Function0) objI, c0814p2, 0, 1);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "emailSentScreen");
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-2099534640, new com.quizlet.explanations.questiondetail.ui.composables.m(24, function0), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, c0374a, androidx.compose.runtime.internal.e.e(1476630299, new com.quizlet.features.questiontypes.mcq.ui.c(7, email, function0), c0814p2), c0814p, 805306416, 188);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.emailsent.ui.a(qVar2, email, function0, i, 0);
        }
    }

    public static void c(String str, int i, String str2, String str3) {
        OTLogger.c(str3, i, str + str2);
    }
}
