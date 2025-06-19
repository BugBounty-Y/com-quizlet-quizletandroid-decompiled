package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
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
import com.quizlet.features.folders.composables.C4252h;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String text, Function1 function1) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1418749044);
        int i2 = i | (c0814p2.f(text) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            androidx.compose.ui.q qVarN = androidx.compose.foundation.layout.K0.n(AbstractC0460p.f(qVar, j, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g)), com.quizlet.themes.m.f0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p2, 48);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarN);
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
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.material3.Q4.b(text, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k, c0814p2, i2 & 14, 0, 65528);
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.q();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f, 5);
            String strD = AbstractC3106b5.d(c0814p2, R.string.refresh);
            c0814p2.X(1587331369);
            boolean z = (i2 & 896) == 256;
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.facebook.a(12, function1);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(strD, qVarY, (Function0) objI, false, null, null, 0L, 0L, null, null, null, c0814p2, 0, 0, 4088);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4252h(i, 0, qVar, text, function1);
        }
    }
}
