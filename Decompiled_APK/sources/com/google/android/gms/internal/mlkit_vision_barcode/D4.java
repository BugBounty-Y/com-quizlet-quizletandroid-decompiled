package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        String text = str;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(873176697);
        int i2 = i | (c0814p2.f(text) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p2, 48);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
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
            C0776c.E(c0814p2, qVarC2, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            androidx.compose.ui.q qVarN = androidx.compose.foundation.layout.K0.n(AbstractC0460p.f(nVar, j, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g)), com.quizlet.themes.m.f0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p2.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p2, qVarN);
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, c0912h);
            C0776c.E(c0814p2, interfaceC0803j0L2, c0912h2);
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h3);
            }
            C0776c.E(c0814p2, qVarC3, c0912h4);
            C0418x c0418x = C0418x.a;
            mVar.q();
            text = str;
            androidx.compose.material3.Q4.b(text, c0418x.a(AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.i), androidx.compose.ui.b.e), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k, c0814p2, i2 & 14, 0, 65528);
            c0814p = c0814p2;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(text, qVar, i, 3);
        }
    }

    public static final void b(androidx.compose.runtime.changelist.L l, int i, Object obj) {
        l.f[(l.g - l.b[l.c - 1].b) + i] = obj;
    }

    public static final void c(androidx.compose.runtime.changelist.L l, int i, Object obj, int i2, Object obj2) {
        int i3 = l.g - l.b[l.c - 1].b;
        Object[] objArr = l.f;
        objArr[i + i3] = obj;
        objArr[i3 + i2] = obj2;
    }

    public static final void d(androidx.compose.runtime.changelist.L l, Object obj, Object obj2, Object obj3) {
        int i = l.g - l.b[l.c - 1].b;
        Object[] objArr = l.f;
        objArr[i] = obj;
        objArr[i + 1] = obj2;
        objArr[i + 2] = obj3;
    }
}
