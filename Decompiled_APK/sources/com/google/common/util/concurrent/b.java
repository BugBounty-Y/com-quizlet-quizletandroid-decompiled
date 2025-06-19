package com.google.common.util.concurrent;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.I0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.focus.h;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.buttons.U;
import com.quizlet.assembly.compose.input.o;
import com.quizlet.assembly.compose.menu.i;
import com.quizlet.assembly.compose.modals.t;
import com.quizlet.explanations.questiondetail.ui.composables.r;
import com.quizlet.explanations.questiondetail.ui.composables.s;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.f;
import com.quizlet.themes.g;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, int i2, InterfaceC0806l interfaceC0806l, q qVar) {
        q qVar2;
        int i3;
        q qVar3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-292550968);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = (c0814p2.f(qVar2) ? 4 : 2) | i;
        }
        if ((i3 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar3 = qVar2;
        } else {
            qVar3 = i4 != 0 ? n.b : qVar2;
            c0814p = c0814p2;
            Q4.b(AbstractC3106b5.d(c0814p2, R.string.question_detail_search_card_header), qVar3, ((com.quizlet.themes.b) c0814p2.j(g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((f) c0814p2.j(w.b)).f, c0814p, (i3 << 3) & ContentType.LONG_FORM_ON_DEMAND, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new r(qVar3, i, i2, 0);
        }
    }

    public static final void b(int i, int i2, InterfaceC0806l interfaceC0806l, q qVar, Function1 function1) {
        int i3;
        int i4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1649200577);
        if ((((c0814p.f(qVar) ? 4 : 2) | i2 | (c0814p.h(function1) ? 32 : 16) | 128) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            i4 = i;
        } else {
            c0814p.S();
            int i5 = i2 & 1;
            V v = C0804k.a;
            if (i5 == 0 || c0814p.w()) {
                i3 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i3 = i;
            }
            c0814p.q();
            h hVar = (h) c0814p.j(AbstractC0955m0.g);
            c0814p.X(-229105608);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z("");
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = Z.g(-229103206, c0814p, false);
            if (objG == v) {
                objG = new t(interfaceC0773a0, 1);
                c0814p.i0(objG);
            }
            Function1 function12 = (Function1) objG;
            Object objG2 = Z.g(-229100891, c0814p, false);
            if (objG2 == v) {
                objG2 = new androidx.work.impl.utils.q(hVar, function1, interfaceC0773a0, 9);
                c0814p.i0(objG2);
            }
            c0814p.p(false);
            q qVarC = K0.c(qVar, 1.0f);
            m.g.d();
            int i6 = i3;
            i4 = i6;
            Z1.c(qVarC, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g), Z1.o(((com.quizlet.themes.b) c0814p.j(g.a)).x0, 0L, 0L, c0814p, 0, 14), null, null, androidx.compose.runtime.internal.e.e(-1338444237, new s(i6, function12, (Function0) objG2, interfaceC0773a0, 0), c0814p), c0814p, 196608, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(i4, i2, qVar, function1);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-400330084);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            W4.a(AbstractC3106b5.d(c0814p, R.string.search), qVar, function0, false, null, null, null, null, null, false, c0814p, (i2 << 3) & 1008, 1016);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new U(qVar, function0, i, 2);
        }
    }

    public static final void d(String str, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1903153949);
        int i2 = i | (c0814p.f(str) ? 4 : 2);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            n nVar = n.b;
            q qVarC = K0.c(nVar, 1.0f);
            m mVar = m.g;
            mVar.s();
            float f = j.h;
            mVar.p();
            q qVarV = AbstractC0382e.v(qVarC, f, j.j);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarV);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            a(0, 1, c0814p, null);
            mVar.q();
            f((i2 & 14) | 3456, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), str, function0, function1);
            mVar.s();
            q qVarC3 = K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f);
            function02 = function0;
            c(48, c0814p, qVarC3, function02);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.q(str, function1, function02, i, 1);
        }
    }

    public static final void e(String str, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1384571271);
        int i2 = i | (c0814p.f(str) ? 4 : 2);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            n nVar = n.b;
            q qVarC = K0.c(nVar, 1.0f);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            C0380d c0380d = AbstractC0398m.a;
            G0 g0B = E0.b(c0380d, hVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            I0 i0 = I0.a;
            q qVarA = i0.a(nVar, 1.0f, true);
            m mVar = m.g;
            mVar.p();
            float f = j.j;
            mVar.p();
            mVar.p();
            q qVarY = AbstractC0382e.y(qVarA, f, f, DefinitionKt.NO_Float_VALUE, f, 4);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            mVar.p();
            a(0, 0, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 11));
            mVar.q();
            q qVarY2 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            G0 g0B2 = E0.b(c0380d, hVar, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarY2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC4, c0912h4);
            f((i2 & 14) | 3456, c0814p, i0.a(nVar, 1.0f, true), str, function0, function1);
            mVar.u();
            function02 = function0;
            c(48, c0814p, AbstractC0382e.y(nVar, j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), function02);
            c0814p.p(true);
            c0814p.p(true);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.bg_question_detail_search_card, c0814p, 0);
            long j = ((com.quizlet.themes.b) c0814p.j(g.a)).y0;
            AbstractC0460p.c(bVarA, null, null, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(F.A(j), F.E(5))), c0814p, 48, 60);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.q(str, function1, function02, i, 0);
        }
    }

    public static final void f(int i, InterfaceC0806l interfaceC0806l, q qVar, String str, Function0 function0, Function1 function1) {
        String str2;
        int i2;
        Function0 function02;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-89594360);
        if ((i & 6) == 0) {
            str2 = str;
            i2 = (c0814p2.f(str2) ? 4 : 2) | i;
        } else {
            str2 = str;
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function02 = function0;
            i2 |= c0814p2.h(function02) ? 2048 : 1024;
        } else {
            function02 = function0;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            q qVarG = N.G(qVar, "QuestionDetailSearchCard.SearchInput");
            String strD = AbstractC3106b5.d(c0814p2, R.string.question_detail_search_card_input_hint);
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            c0814p = c0814p2;
            AbstractC3745v5.a(str2, qVarG, function1, null, strD, 0, 0, null, null, 3, 0, function02, null, false, false, com.quizlet.ui.resources.icons.d.H(c0814p2), 0, o.a, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p, i2 & 910, ((i2 >> 3) & 896) | 6, 0, 8055784);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new i((Object) str, (Object) qVar, function1, (Object) function0, i, 2);
        }
    }
}
