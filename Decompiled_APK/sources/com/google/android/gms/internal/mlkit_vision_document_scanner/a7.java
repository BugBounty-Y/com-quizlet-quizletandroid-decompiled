package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class a7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(boolean z, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        long jA;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(646434395);
        if ((((c0814p.g(z) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p.X(614189070);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_close_x, c0814p, 0);
            c0814p.p(false);
            String strD = AbstractC3106b5.d(c0814p, R.string.incorrect);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jO = ((com.quizlet.themes.b) c0814p.j(b)).o();
            if (z) {
                c0814p.X(818855452);
                c0814p.X(-863555110);
                bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_check, c0814p, 0);
                c0814p.p(false);
                strD = AbstractC3106b5.d(c0814p, R.string.correct);
                jA = ((com.quizlet.themes.b) c0814p.j(b)).b.l();
                c0814p.p(false);
            } else {
                c0814p.X(819020558);
                jA = ((com.quizlet.themes.b) c0814p.j(b)).b.a();
                c0814p.p(false);
            }
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar3, jA, androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.d(qVarF, 36), 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i2 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            C0853m c0853m = new C0853m(jO, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jO, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jO), androidx.compose.ui.graphics.F.E(5)));
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar3, "image");
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarG, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 10);
            mVar.i();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVarY, com.quizlet.ui.resources.designsystem.generated.h.f);
            String str = strD;
            AbstractC0460p.c(bVarA, str, qVarK, null, null, DefinitionKt.NO_Float_VALUE, c0853m, c0814p, 0, 56);
            androidx.compose.material3.Q4.b(str, null, jO, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.internal.a(z, nVar2, i, 3);
        }
    }
}
