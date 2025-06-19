package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.material3.AbstractC0684m3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.work.ThreadFactoryC1423d;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.quizlet.features.practicetest.takingtest.data.C4407a;
import com.quizlet.features.practicetest.takingtest.data.C4408b;
import com.quizlet.features.practicetest.takingtest.data.C4411e;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.r2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3386r2 {
    public static final void a(C4408b question, Function0 selectedAnswer, Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function12;
        boolean z;
        Function1 onSelectAnswer = function1;
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(selectedAnswer, "selectedAnswer");
        Intrinsics.checkNotNullParameter(onSelectAnswer, "onSelectAnswer");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(719710974);
        int i2 = i | (c0814p.f(question) ? 4 : 2) | (c0814p.h(selectedAnswer) ? 32 : 16) | (c0814p.h(onSelectAnswer) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            ArrayList arrayList = question.a;
            Object[] objArr = new Object[0];
            c0814p.X(1992709446);
            boolean z2 = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z2 || objI == v) {
                objI = new com.braze.support.u(23, selectedAnswer);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Object objD = L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            c0814p = c0814p;
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objD;
            Integer num = (Integer) interfaceC0773a0.component1();
            Function1 function1Component2 = interfaceC0773a0.component2();
            androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(androidx.compose.ui.platform.N.G(qVar, "practice_test_taking_test_mcq_answers"), false, androidx.compose.foundation.selection.a.a);
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.u();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, gVar, c0814p, 0);
            int i3 = c0814p.P;
            boolean z3 = true;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarA);
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
            c0814p.X(170666417);
            Iterator it2 = arrayList.iterator();
            int i4 = 0;
            while (it2.hasNext()) {
                Object next = it2.next();
                int i5 = i4 + 1;
                if (i4 < 0) {
                    kotlin.collections.B.p();
                    throw null;
                }
                C4407a c4407a = (C4407a) next;
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                boolean z4 = (num != null && i4 == num.intValue()) ? z3 : false;
                Iterator it3 = it2;
                androidx.compose.ui.semantics.h hVar = new androidx.compose.ui.semantics.h(3);
                c0814p.X(-755296755);
                androidx.compose.ui.g gVar2 = gVar;
                boolean zF = c0814p.f(function1Component2) | c0814p.d(i4) | ((i2 & 896) == 256 ? z3 : false) | c0814p.h(c4407a);
                Object objI2 = c0814p.I();
                if (zF || objI2 == v) {
                    objI2 = new com.quizlet.features.practicetest.takingtest.f(function1Component2, i4, onSelectAnswer, c4407a);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                androidx.compose.ui.q qVarA2 = androidx.compose.ui.a.a(qVarC2, new androidx.compose.foundation.selection.b(z4, z3, hVar, (Function0) objI2));
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
                int i6 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarA2);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0912h c0912h2 = C0914j.f;
                C0776c.E(c0814p, g0B, c0912h2);
                C0912h c0912h3 = C0914j.e;
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h3);
                C0912h c0912h4 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                    android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h4);
                }
                C0912h c0912h5 = C0914j.d;
                C0776c.E(c0814p, qVarC3, c0912h5);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.i();
                float f = com.quizlet.ui.resources.designsystem.generated.h.f;
                mVar.m();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.n;
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12);
                if (num != null && i4 == num.intValue()) {
                    function12 = function1Component2;
                    z = true;
                } else {
                    function12 = function1Component2;
                    z = false;
                }
                Function1 function13 = function12;
                androidx.compose.runtime.V v2 = v;
                int i7 = i2;
                AbstractC0684m3.a(z, null, qVarY, false, null, c0814p, 48, 56);
                mVar.m();
                mVar.i();
                mVar.u();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.g;
                mVar.m();
                androidx.compose.ui.q qVarX = AbstractC0382e.x(nVar, f3, f2, f, f2);
                androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, gVar2, c0814p, 0);
                int i8 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarX);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, bA2, c0912h2);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h3);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h4);
                }
                C0776c.E(c0814p, qVarC4, c0912h5);
                C0814p c0814p2 = c0814p;
                Q4.b(c4407a.a, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).n, c0814p2, 0, 0, 65530);
                c0814p = c0814p2;
                c0814p.X(-1542710551);
                ArrayList arrayList2 = c4407a.b;
                if (arrayList2 != null && !arrayList2.isEmpty()) {
                    String str = ((C4411e) CollectionsKt.L(arrayList2)).a;
                    String str2 = ((C4411e) CollectionsKt.L(arrayList2)).b;
                    mVar.u();
                    r3.a(str, str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, null, null, c0814p, 0, 2040);
                    c0814p = c0814p;
                }
                androidx.compose.ui.node.B.s(c0814p, false, true, true);
                onSelectAnswer = function1;
                gVar = gVar2;
                z3 = true;
                i4 = i5;
                it2 = it3;
                v = v2;
                function1Component2 = function13;
                i2 = i7;
            }
            c0814p.p(false);
            c0814p.p(z3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(question, selectedAnswer, function1, qVar, i, 22);
        }
    }

    public static final ExecutorService b(boolean z) {
        ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(Math.max(2, Math.min(Runtime.getRuntime().availableProcessors() - 1, 4)), new ThreadFactoryC1423d(z));
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool, "newFixedThreadPool(\n    …)),\n        factory\n    )");
        return executorServiceNewFixedThreadPool;
    }

    public static String c(String str) {
        return str != null ? str.toLowerCase(Locale.ENGLISH) : "";
    }

    public static String d(String str) {
        return c(str).trim();
    }
}
