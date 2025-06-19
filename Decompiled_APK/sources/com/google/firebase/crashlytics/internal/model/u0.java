package com.google.firebase.crashlytics.internal.model;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.S0;
import androidx.compose.foundation.layout.U0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class u0 {
    public static final /* synthetic */ int a = 0;

    public static final void a(Function0 onSearchSetClick, Function0 onCreateSetClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onSearchSetClick, "onSearchSetClick");
        Intrinsics.checkNotNullParameter(onCreateSetClick, "onCreateSetClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(58002993);
        int i2 = i | (c0814p.h(onSearchSetClick) ? 4 : 2) | (c0814p.h(onCreateSetClick) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.ui.draw.g.j(nVar3, com.quizlet.themes.m.j, null, 30), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), androidx.compose.ui.graphics.F.a);
            mVar.t();
            float f = com.quizlet.ui.resources.designsystem.generated.j.k;
            mVar.q();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarF, com.quizlet.ui.resources.designsystem.generated.j.i, f);
            c0814p.X(360309978);
            WeakHashMap weakHashMap = S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = U0.b(qVarV, c0374a);
            C0380d c0380d = AbstractC0398m.a;
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f2), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarB);
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
            String strD = AbstractC3106b5.d(c0814p, R.string.subject_search_create_set_secondary_message);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            Q4.b(strD, androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).j, c0814p, 48, 0, 65020);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.subject_search_create_primary_message), androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).e, c0814p, 48, 0, 65020);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.subject_search_create_button_message);
            androidx.compose.runtime.B b2 = com.quizlet.themes.e.a;
            ((com.quizlet.themes.d) c0814p.j(b2)).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarH = com.quizlet.ui.resources.icons.d.H(c0814p);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            mVar.s();
            W4.a(strD2, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), onSearchSetClick, false, null, null, null, null, bVarH, false, c0814p, (i2 << 6) & 896, 760);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.create);
            ((com.quizlet.themes.d) c0814p.j(b2)).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarF = com.quizlet.ui.resources.icons.d.F(c0814p);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            mVar.u();
            c0814p = c0814p;
            Y4.a(strD3, AbstractC0382e.y(qVarC3, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), onCreateSetClick, false, false, null, null, 0L, 0L, null, null, bVarF, false, c0814p, (i2 << 3) & 896, 0, 6136);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(onSearchSetClick, onCreateSetClick, nVar2, i, 9);
        }
    }
}
