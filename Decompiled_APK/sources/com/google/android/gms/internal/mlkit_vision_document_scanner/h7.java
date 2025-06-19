package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0384f;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.foundation.layout.VerticalAlignElement;
import androidx.compose.foundation.layout.z0;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
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
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.C4757a;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.InterfaceC4758b;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class h7 {
    public static final void a(Function0 function0, C4757a c4757a, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1609470762);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(c4757a) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(539002633);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.composable.a(20, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVar, false, null, (Function0) objI, 7);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
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
            String strD = AbstractC3106b5.d(c0814p, R.string.test_mode_settings_answer_with_prompt);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).j;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, androidx.compose.ui.n.b, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 48, 0, 65528);
            c4757a.getClass();
            ArrayList stringsToCombine = new ArrayList();
            if (c4757a.a.a) {
                stringsToCombine.add(c4757a.g);
            }
            if (c4757a.b.a) {
                stringsToCombine.add(c4757a.h);
            }
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar = c4757a.c;
            if (jVar != null && jVar.a) {
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                stringsToCombine.add(new com.quizlet.qutils.string.f(R.string.location, C4933y.P(args)));
            }
            Intrinsics.checkNotNullParameter(stringsToCombine, "strings");
            Intrinsics.checkNotNullParameter(", ", "separator");
            Intrinsics.checkNotNullParameter(stringsToCombine, "stringsToCombine");
            Intrinsics.checkNotNullParameter(", ", "separator");
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(context, "context");
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(stringsToCombine, 10));
            Iterator it2 = stringsToCombine.iterator();
            while (it2.hasNext()) {
                arrayList.add(((com.quizlet.qutils.string.g) it2.next()).a(context));
            }
            String string = CollectionsKt.S(arrayList, ", ", null, null, new com.quizlet.qutils.android.f(1), 30).toString();
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            com.quizlet.themes.m.g.w();
            androidx.compose.material3.Q4.b(string, AbstractC0382e.y(layoutWeightElement, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(5), 0L, 2, false, 1, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 0, 3120, 54776);
            c0814p = c0814p;
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarO = com.quizlet.ui.resources.icons.d.o(c0814p);
            long j = ((com.quizlet.themes.b) c0814p.j(b2)).k;
            AbstractC0460p.c(bVarO, null, null, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j), androidx.compose.ui.graphics.F.E(5))), c0814p, 48, 60);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 24, qVar, (Object) function0, (Object) c4757a);
        }
    }

    public static final void b(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1025237182);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.f(str) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            C0776c.E(c0814p, qVarC, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
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
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).k;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, l, c0814p, i2 & 14, 3120, 55290);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.test_mode_settings_header), null, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).e, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            AbstractC0460p.c(com.quizlet.themes.e.a(c0814p).d.A(c0814p), null, null, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 124);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(str, qVar, i, 6);
        }
    }

    public static final void c(Integer num, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1034087843);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(num) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else if (num != null) {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            String strC = AbstractC3106b5.c(R.string.test_mode_last_score_label, new Object[]{num}, c0814p);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).g;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strC, null, ((com.quizlet.themes.b) c0814p.j(b)).R, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.material3.Z1.g(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.h, ((com.quizlet.themes.b) c0814p.j(b)).b.b(), c0814p, 0, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(num, qVar, i, 28);
        }
    }

    public static final void d(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(68675294);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m.g.g();
            AbstractC0666j3.a(androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.ui.resources.designsystem.generated.h.h), "loadingIndicator"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).k, 2, 0L, 0, c0814p, 384, 24);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 22, qVar);
        }
    }

    public static final void e(androidx.compose.ui.text.input.A a, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar, int i, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-825399967);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.f(a) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            yVar2 = yVar;
            i3 |= c0814p2.h(yVar2) ? 32 : 16;
        } else {
            yVar2 = yVar;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.d(i) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.focus.h hVar = (androidx.compose.ui.focus.h) c0814p2.j(AbstractC0955m0.g);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p2, 48);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            Function0 function0 = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(function0);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p2, R.string.test_mode_question_count);
            AbstractC0809m0 abstractC0809m0 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(abstractC0809m0)).j;
            AbstractC0809m0 abstractC0809m02 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, null, ((com.quizlet.themes.b) c0814p2.j(abstractC0809m02)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65530);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            com.quizlet.themes.m.g.w();
            androidx.compose.material3.Q4.b(AbstractC3106b5.c(R.string.test_mode_question_count_max, new Object[]{Integer.valueOf(i)}, c0814p2), AbstractC0382e.y(layoutWeightElement, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), ((com.quizlet.themes.b) c0814p2.j(abstractC0809m02)).b.f(), 0L, null, 0L, null, 0L, 2, false, 1, 0, null, ((com.quizlet.themes.f) c0814p2.j(abstractC0809m0)).o, c0814p2, 0, 3120, 55288);
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, 100, 1);
            c0814p2.X(-689822019);
            boolean zH = c0814p2.h(hVar);
            Object objI = c0814p2.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.universaluploadflow.flashcards.e(hVar, 1);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            AbstractC3745v5.c(a, qVarQ, yVar2, 0, null, 0, 3, (Function0) objI, 6, null, c0814p2, (i3 & 14) | 805306416 | ((i3 << 3) & 896));
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(a, yVar, i, qVar, i2);
        }
    }

    public static final void f(com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar2, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar3, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1837705510);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(jVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(jVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(jVar3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            k(AbstractC3106b5.d(c0814p, R.string.test_mode_true_false), jVar, nVar, c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 384);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            k(AbstractC3106b5.d(c0814p, R.string.test_mode_multiple_choice), jVar2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND);
            mVar.p();
            k(AbstractC3106b5.d(c0814p, R.string.test_mode_written), jVar3, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(jVar, jVar2, jVar3, qVar, i, 5);
        }
    }

    public static final void g(final String str, final androidx.compose.ui.text.input.A a, final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar2, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar3, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar4, C4757a c4757a, final boolean z, final Function0 function0, final boolean z2, final Function0 function02, final int i, final Integer num, InterfaceC0806l interfaceC0806l, final int i2) {
        C0814p c0814p;
        final C4757a c4757a2 = c4757a;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1032224569);
        int i3 = i2 | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(a) ? 32 : 16) | (c0814p2.h(yVar) ? 256 : 128) | (c0814p2.f(jVar) ? 2048 : 1024) | (c0814p2.f(jVar2) ? 16384 : 8192) | (c0814p2.f(jVar3) ? 131072 : 65536) | (c0814p2.f(jVar4) ? 1048576 : 524288) | (c0814p2.h(c4757a2) ? 8388608 : 4194304) | (c0814p2.g(z) ? 67108864 : 33554432) | (c0814p2.h(function0) ? 536870912 : 268435456);
        char c = c0814p2.g(z2) ? (char) 4 : (char) 2;
        char c2 = ' ';
        if (!c0814p2.h(function02)) {
            c2 = 16;
        }
        int i4 = c | c2 | (c0814p2.d(i) ? (char) 256 : (char) 128) | (c0814p2.f(num) ? (char) 2048 : (char) 1024);
        if ((i3 & 306783379) == 306783378 && (i4 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p2, 6, 6);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1705568396, new com.quizlet.quizletandroid.ui.studymodes.testmode.start.s(z2, function0, z), c0814p2);
            c0814p = c0814p2;
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.t tVar = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.t(str, a, yVar, jVar, jVar2, jVar3, jVar4, xVarH, function02, i, num, c4757a2);
            c4757a2 = c4757a2;
            AbstractC0725t3.a(null, null, dVarE, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(1708049238, tVar, c0814p), c0814p2, 805306752, 507);
            g7.a(xVarH, c4757a2, null, c0814p, ((i3 >> 18) & ContentType.LONG_FORM_ON_DEMAND) | 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(str, a, yVar, jVar, jVar2, jVar3, jVar4, c4757a2, z, function0, z2, function02, i, num, i2) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.start.q
                public final /* synthetic */ String a;
                public final /* synthetic */ androidx.compose.ui.text.input.A b;
                public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y c;
                public final /* synthetic */ j d;
                public final /* synthetic */ j e;
                public final /* synthetic */ j f;
                public final /* synthetic */ j g;
                public final /* synthetic */ C4757a h;
                public final /* synthetic */ boolean i;
                public final /* synthetic */ Function0 j;
                public final /* synthetic */ boolean k;
                public final /* synthetic */ Function0 l;
                public final /* synthetic */ int m;
                public final /* synthetic */ Integer n;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    String str2 = this.a;
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar2 = this.c;
                    int i5 = this.m;
                    Integer num2 = this.n;
                    h7.g(str2, this.b, yVar2, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, i5, num2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void h(String str, final androidx.compose.ui.text.input.A a, final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar2, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar3, final com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar4, final com.quizlet.assembly.compose.modals.x xVar, final Function0 function0, final int i, Integer num, C4757a c4757a, final androidx.compose.foundation.layout.z0 z0Var, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        int i4;
        String str2;
        Integer num2;
        androidx.compose.runtime.B b;
        androidx.compose.ui.q qVar;
        final C4757a c4757a2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-877322407);
        int i5 = i2 | (c0814p.f(str) ? 4 : 2) | (c0814p.f(a) ? 32 : 16) | (c0814p.h(yVar) ? 256 : 128) | (c0814p.f(jVar) ? 2048 : 1024) | (c0814p.f(jVar2) ? 16384 : 8192) | (c0814p.f(jVar3) ? 131072 : 65536) | (c0814p.f(jVar4) ? 1048576 : 524288) | (c0814p.h(xVar) ? 8388608 : 4194304) | (c0814p.h(function0) ? 67108864 : 33554432) | (c0814p.d(i) ? 536870912 : 268435456);
        if ((i3 & 6) == 0) {
            i4 = i3 | (c0814p.f(num) ? 4 : 2);
        } else {
            i4 = i3;
        }
        if ((i3 & 48) == 0) {
            i4 |= c0814p.h(c4757a) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            i4 |= c0814p.f(z0Var) ? 256 : 128;
        }
        if ((i5 & 306783379) == 306783378 && (i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
            num2 = num;
            c4757a2 = c4757a;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarT = AbstractC0382e.t(nVar, z0Var);
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            int i6 = i4;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarT, ((com.quizlet.themes.b) c0814p.j(b2)).b.h(), androidx.compose.ui.graphics.F.a);
            C0384f c0384f = AbstractC0398m.c;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.foundation.N0 scrollState = AbstractC0460p.r(c0814p);
            androidx.compose.ui.q scrollVerticalFadingEdges = AbstractC0460p.u(androidx.compose.foundation.layout.C.a(nVar, 1.0f), scrollState, false, 14);
            long jN = ((com.quizlet.themes.b) c0814p.j(b2)).b.n();
            Intrinsics.checkNotNullParameter(scrollVerticalFadingEdges, "$this$scrollVerticalFadingEdges");
            Intrinsics.checkNotNullParameter(scrollState, "scrollState");
            androidx.compose.ui.q qVarF2 = com.google.android.gms.internal.mlkit_vision_barcode.M5.f(scrollVerticalFadingEdges, scrollState, jN, com.quizlet.themes.m.n);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarF2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12);
            c0814p.X(1071639478);
            boolean z = (i5 & 234881024) == 67108864;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(19, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarY, false, null, (Function0) objI, 7);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.material.C.a(com.quizlet.ui.resources.icons.d.u(c0814p), AbstractC3106b5.d(c0814p, R.string.back), qVarL, ((com.quizlet.themes.b) c0814p.j(b2)).k, c0814p, 0);
            mVar.s();
            str2 = str;
            b(str2, AbstractC0382e.u(nVar, f), c0814p, i5 & 14);
            mVar.s();
            mVar.s();
            num2 = num;
            c(num2, AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 10), c0814p, i6 & 14);
            mVar.s();
            e(a, yVar, i, AbstractC0382e.u(nVar, f), c0814p, ((i5 >> 3) & 126) | ((i5 >> 21) & 896));
            mVar.s();
            k(AbstractC3106b5.d(c0814p, R.string.test_mode_instant_feedback), jVar, AbstractC0382e.u(nVar, f), c0814p, (i5 >> 6) & ContentType.LONG_FORM_ON_DEMAND);
            mVar.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            c0814p.X(1071686291);
            boolean z2 = (i5 & 29360128) == 8388608 || c0814p.h(xVar);
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                b = b2;
                qVar = qVarU;
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.a(0, xVar, com.quizlet.assembly.compose.modals.x.class, "show", "show(Landroid/os/Bundle;)V", 0, 1);
                c0814p.i0(aVar);
                objI2 = aVar;
            } else {
                qVar = qVarU;
                b = b2;
            }
            c0814p.p(false);
            c4757a2 = c4757a;
            a((Function0) objI2, c4757a2, qVar, c0814p, i6 & ContentType.LONG_FORM_ON_DEMAND);
            mVar.s();
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar, f, f, f, DefinitionKt.NO_Float_VALUE, 8);
            float f2 = com.quizlet.themes.m.h;
            long jB = ((com.quizlet.themes.b) c0814p.j(b)).b.b();
            c0814p = c0814p;
            androidx.compose.material3.Z1.g(qVarY2, f2, jB, c0814p, 0, 0);
            mVar.s();
            f(jVar2, jVar3, jVar4, AbstractC0382e.u(nVar, f), c0814p, (i5 >> 12) & 1022);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final String str3 = str2;
            final Integer num3 = num2;
            c0813o0R.d = new Function2(str3, a, yVar, jVar, jVar2, jVar3, jVar4, xVar, function0, i, num3, c4757a2, z0Var, i2, i3) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.start.r
                public final /* synthetic */ String a;
                public final /* synthetic */ androidx.compose.ui.text.input.A b;
                public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y c;
                public final /* synthetic */ j d;
                public final /* synthetic */ j e;
                public final /* synthetic */ j f;
                public final /* synthetic */ j g;
                public final /* synthetic */ com.quizlet.assembly.compose.modals.x h;
                public final /* synthetic */ Function0 i;
                public final /* synthetic */ int j;
                public final /* synthetic */ Integer k;
                public final /* synthetic */ C4757a l;
                public final /* synthetic */ z0 m;
                public final /* synthetic */ int n;

                {
                    this.n = i3;
                }

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(16777217);
                    int iH2 = C0776c.H(this.n);
                    String str4 = this.a;
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar2 = this.c;
                    C4757a c4757a3 = this.l;
                    z0 z0Var2 = this.m;
                    h7.h(str4, this.b, yVar2, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, c4757a3, z0Var2, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void i(com.quizlet.quizletandroid.ui.studymodes.testmode.start.A viewModel, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-487100189);
        int i2 = (c0814p.f(viewModel) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            j(viewModel, (com.quizlet.quizletandroid.ui.studymodes.testmode.start.B) C0776c.m(viewModel.h, c0814p).getValue(), c0814p, i2 & 14);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(viewModel, i, 14);
        }
    }

    public static final void j(com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a, com.quizlet.quizletandroid.ui.studymodes.testmode.start.B uiState, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        int i2;
        androidx.compose.runtime.V v;
        com.quizlet.quizletandroid.ui.studymodes.testmode.start.A viewModel = a;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(459765184);
        int i3 = (c0814p2.f(viewModel) ? 4 : 2) | i | (c0814p2.f(uiState) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else if (uiState instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) {
            c0814p2.X(-680387734);
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) uiState;
            String str = cVar.a;
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = cVar.d;
            c0814p2.X(-576115065);
            int i4 = i3 & 14;
            boolean z = i4 == 4;
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (z || objI == v2) {
                i2 = i4;
                v = v2;
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, InterfaceC4758b.class, "onStartButtonClicked", "onStartButtonClicked()V", 0, 18);
                c0814p2.i0(lVar);
                objI = lVar;
            } else {
                i2 = i4;
                v = v2;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI;
            c0814p2.p(false);
            c0814p2.X(-576112992);
            boolean z2 = i2 == 4;
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == v) {
                viewModel = a;
                objI2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, InterfaceC4758b.class, "onBackPressed", "onBackPressed()V", 0, 19);
                c0814p2.i0(objI2);
            } else {
                viewModel = a;
            }
            c0814p2.p(false);
            g(str, cVar.b, yVar, cVar.e, cVar.f, cVar.g, cVar.h, cVar.l, cVar.j, (Function0) fVar, cVar.i, (Function0) ((kotlin.reflect.f) objI2), cVar.c, cVar.k, c0814p2, 0);
            c0814p = c0814p2;
            c0814p.p(false);
        } else {
            c0814p = c0814p2;
            if (!(uiState instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.d)) {
                throw com.google.android.gms.measurement.internal.Z.j(-576139083, c0814p, false);
            }
            c0814p.X(-576108585);
            d(null, c0814p, 0);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(viewModel, uiState, i, 0);
        }
    }

    public static final void k(String text, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.quizletandroid.ui.studymodes.testmode.start.j switchData = jVar;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(switchData, "switchData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2057342501);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(switchData) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            androidx.compose.material3.Q4.b(text, new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true).g(new VerticalAlignElement(androidx.compose.ui.b.k)), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j, c0814p, i2 & 14, 0, 65528);
            switchData = jVar;
            c0814p = c0814p;
            S4.a(switchData.a, null, switchData.b, false, c0814p, 0, 10);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 23, qVar, (Object) text, (Object) switchData);
        }
    }
}
