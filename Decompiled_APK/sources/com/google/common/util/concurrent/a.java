package com.google.common.util.concurrent;

import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.navigation.compose.C1279l;
import com.comscore.streaming.AdvertisementType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.quizlet.explanations.questiondetail.ui.composables.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.f;
import com.quizlet.themes.g;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    public static final void a(kotlinx.collections.immutable.b textbooks, q qVar, boolean z, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        boolean z2 = z;
        Intrinsics.checkNotNullParameter(textbooks, "textbooks");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1162994631);
        int i2 = i | (c0814p.h(textbooks) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.g(z2) ? 256 : 128) | (c0814p.h(function2) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            V v = C0804k.a;
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            n nVar = n.b;
            m mVar = m.g;
            mVar.s();
            float f = j.h;
            Q4.b(AbstractC3106b5.d(c0814p, R.string.recommended_textbook_solutions_title), AbstractC0382e.w(nVar, f, DefinitionKt.NO_Float_VALUE, 2), ((com.quizlet.themes.b) c0814p.j(g.a)).b.e(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, ((f) c0814p.j(w.b)).f, c0814p, 0, 3120, 55288);
            c0814p = c0814p;
            mVar.s();
            q qVarC2 = K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f);
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f);
            mVar.s();
            A0 a0C = AbstractC0382e.c(f, DefinitionKt.NO_Float_VALUE, 2);
            c0814p.X(1358588268);
            boolean zH = ((i2 & 7168) == 2048) | c0814p.h(textbooks) | ((i2 & 896) == 256);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                z2 = z;
                objI = new C1279l(textbooks, z2, function2, 1);
                c0814p.i0(objI);
            } else {
                z2 = z;
            }
            c0814p.p(false);
            AbstractC3137f0.b(qVarC2, null, a0C, c0392jG, null, null, false, (Function1) objI, c0814p, 0, AdvertisementType.BRANDED_AS_CONTENT);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new o(textbooks, qVar, z2, function2, i, 0);
        }
    }
}
