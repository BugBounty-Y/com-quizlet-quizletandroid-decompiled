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
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import com.quizlet.features.folders.composables.AbstractC4260p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class G4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, com.quizlet.features.folders.data.Q0 q0, Function1 function1) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(797160556);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(q0) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            String str = q0.d;
            if (str != null && !StringsKt.O(str)) {
                String strC = AbstractC3106b5.c(R.string.folder_by, new Object[]{str}, c0814p);
                androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.s();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.i, 5);
                c0814p.X(-206497578);
                boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p.h(q0);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    objI = new com.quizlet.data.repository.explanations.exercise.a(13, function1, q0);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarY, false, null, (Function0) objI, 7);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
                int i3 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
                androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarL);
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
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                    android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
                }
                C0776c.E(c0814p, qVarC, C0914j.d);
                androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_image_gray400, c0814p, 0);
                androidx.compose.ui.graphics.painter.b bVarA2 = Z4.a(R.drawable.ic_sys_image_gray400, c0814p, 0);
                mVar.h();
                com.google.android.gms.internal.mlkit_vision_camera.r3.b(q0.f, str, androidx.compose.ui.draw.g.c(androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.g), androidx.compose.foundation.shape.e.a), bVarA, bVarA2, c0814p, 0, 32736);
                mVar.u();
                androidx.compose.material3.Q4.b(strC, AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k, c0814p, 0, 0, 65528);
                c0814p = c0814p;
                c0814p.p(true);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(q0, function1, i, 6);
        }
    }

    public static final void b(com.quizlet.features.folders.data.Q0 state, androidx.compose.ui.q qVar, boolean z, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(568034229);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(state) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.animation.E.g(!z, null, androidx.compose.animation.V.c(null, 3), androidx.compose.animation.V.d(null, 3), null, androidx.compose.runtime.internal.e.e(-661913971, new com.quizlet.assembly.compose.input.h(qVar, state, function1, 4), c0814p), c0814p, 200064, 18);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(state, qVar, z, function1, i);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, com.quizlet.features.folders.data.Q0 q0, Function1 function1) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2031724641);
        int i2 = (c0814p.h(function1) ? 4 : 2) | i | (c0814p.h(q0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            switch (AbstractC4260p.a[q0.s.ordinal()]) {
                case 1:
                    c0814p.X(-369509664);
                    a(((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 3) & 14), c0814p, q0, function1);
                    c0814p.p(false);
                    break;
                case 2:
                case 3:
                case 4:
                    c0814p.X(-369503812);
                    d(c0814p, 0);
                    c0814p.p(false);
                    break;
                case 5:
                case 6:
                    c0814p.X(-369500668);
                    e(c0814p, 0);
                    c0814p.p(false);
                    break;
                default:
                    throw com.google.android.gms.measurement.internal.Z.j(-369511605, c0814p, false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(function1, q0, i, 15);
        }
    }

    public static final void d(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(900414132);
        if (i == 0 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strC = AbstractC3106b5.c(R.string.folder_by, new Object[]{AbstractC3106b5.d(c0814p2, R.string.app_name)}, c0814p2);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(strC, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k, c0814p, 0, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 7);
        }
    }

    public static final void e(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-221261108);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            String strD = AbstractC3106b5.d(c0814p, R.string.verified);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarN = com.quizlet.ui.resources.icons.d.N(c0814p);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
            long j = com.quizlet.ui.resources.designsystem.generated.d.C;
            ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
            AbstractC3587b6.a(strD, qVarY, j, com.quizlet.ui.resources.designsystem.generated.d.x, 0L, bVarN, null, c0814p, 0, 80);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 8);
        }
    }

    public static final int f(int i, int i2) {
        return (i >> i2) & 31;
    }
}
