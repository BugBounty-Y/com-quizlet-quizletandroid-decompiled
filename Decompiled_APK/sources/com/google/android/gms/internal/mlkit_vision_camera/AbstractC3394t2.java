package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.appcompat.app.ExecutorC0060p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.material3.AbstractC0725t3;
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
import androidx.work.C1444s;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.assembly.compose.modals.C4103b;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.C4416j;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.WeakHashMap;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.t2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3394t2 {
    public static final void a(C4412f c4412f, InterfaceC4415i interfaceC4415i, Function1 function1, Function1 function12, Function0 function0, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-60454235);
        int i2 = i | (c0814p.h(c4412f) ? 4 : 2) | (c0814p.f(interfaceC4415i) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1321893145);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new com.quizlet.features.practicetest.navigation.a(7);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.animation.E.b(c4412f, null, (Function1) objI, null, null, null, androidx.compose.runtime.internal.e.e(1021090127, new androidx.navigation.compose.L(qVar, interfaceC4415i, function1, function12, function0, 1), c0814p), c0814p, (i2 & 14) | 1573248, 58);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) c4412f, (Object) interfaceC4415i, function1, (InterfaceC4938g) function12, function0, (Object) qVar, i, 8);
        }
    }

    public static final void b(com.quizlet.assembly.compose.modals.x xVar, com.quizlet.features.practicetest.takingtest.data.M m, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1183393816);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(xVar) : c0814p.h(xVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(m) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            PracticeTestConfigurationData practiceTestConfigurationData = m.c;
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_configuration_modal_header);
            c0814p.X(1975598177);
            int i3 = i2 & 14;
            int i4 = i2 & 896;
            boolean z = (i3 == 4 || ((i2 & 8) != 0 && c0814p.h(xVar))) | (i4 == 256);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.practicetest.results.b(xVar, function1);
                c0814p.i0(objI);
            }
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) objI;
            c0814p.p(false);
            c0814p.X(1975605672);
            boolean z2 = (i3 == 4 || ((i2 & 8) != 0 && c0814p.h(xVar))) | (i4 == 256);
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.folders.addtofolder.composables.j(xVar, function1, 7);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            N1.a(xVar, practiceTestConfigurationData.a, m.b, true, null, true, false, strD, m.a, null, false, cVar, (Function0) objI2, null, c0814p, 3080 | i3, 6, 8720);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 26, xVar, m, function1);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, com.quizlet.assembly.compose.modals.x xVar, Function0 function0, Function1 function1, kotlinx.collections.immutable.e eVar) {
        int i2;
        androidx.compose.ui.q qVar2;
        com.quizlet.assembly.compose.modals.x xVar2;
        kotlinx.collections.immutable.e eVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-271247236);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(xVar) : c0814p.h(xVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(eVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
            xVar2 = xVar;
            eVar2 = eVar;
        } else {
            c0814p.X(-1651331387);
            boolean z = (i2 & 7168) == 2048;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l(12, function1);
                c0814p.i0(objI);
            }
            Function1 function12 = (Function1) objI;
            c0814p.p(false);
            c0814p.X(-1651328371);
            int i3 = i2 & 14;
            boolean z2 = (i3 == 4 || ((i2 & 8) != 0 && c0814p.h(xVar))) | ((i2 & 896) == 256);
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new C4103b(xVar, function0, 6);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            int i4 = 8 | i3 | (i2 & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 57344);
            qVar2 = qVar;
            U1.a(i4, c0814p, qVar2, xVar, (Function0) objI2, function12, eVar);
            xVar2 = xVar;
            eVar2 = eVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.common.composables.l(xVar2, eVar2, function0, function1, qVar2, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0193  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01bf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(kotlinx.coroutines.flow.W r29, com.quizlet.features.practicetest.takingtest.viewmodel.a r30, kotlin.jvm.functions.Function2 r31, kotlin.jvm.functions.Function2 r32, kotlin.jvm.functions.Function2 r33, kotlin.jvm.functions.Function0 r34, kotlin.jvm.functions.Function2 r35, kotlin.jvm.functions.Function1 r36, kotlin.jvm.functions.Function0 r37, androidx.compose.runtime.InterfaceC0806l r38, int r39) {
        /*
            Method dump skipped, instructions count: 716
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2.d(kotlinx.coroutines.flow.W, com.quizlet.features.practicetest.takingtest.viewmodel.a, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v42 */
    /* JADX WARN: Type inference failed for: r6v43, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r6v44 */
    public static final void e(com.quizlet.features.practicetest.takingtest.data.F f, kotlinx.coroutines.flow.W w, kotlinx.coroutines.flow.W w2, Function1 function1, Function2 function2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Object obj;
        Function0 function02;
        boolean z;
        Object obj2;
        com.quizlet.features.practicetest.takingtest.data.F f2;
        InterfaceC0773a0 interfaceC0773a0;
        boolean z2;
        boolean z3;
        InterfaceC0773a0 interfaceC0773a02;
        Object obj3;
        ?? r6;
        Object obj4;
        C0814p c0814p;
        Function1 function12 = function1;
        int i3 = 0;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(382155894);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(f) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(w) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(w2) ? 256 : 128;
        }
        int i4 = 3;
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function12) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function2) ? 16384 : 8192;
        }
        if ((i & 196608) == 0) {
            i2 |= c0814p2.h(function0) ? 131072 : 65536;
        }
        if ((i2 & 74899) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            f2 = f;
            function02 = function0;
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(1498756588);
            boolean zH = c0814p2.h(f);
            Object objI = c0814p2.I();
            Object obj5 = objI;
            if (zH || objI == v) {
                com.quizlet.features.practicetest.takingtest.k kVar = new com.quizlet.features.practicetest.takingtest.k(f, i3);
                c0814p2.i0(kVar);
                obj5 = kVar;
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) obj5, c0814p2, 0, 6);
            Boolean boolValueOf = Boolean.valueOf(f.b());
            c0814p2.X(1498759540);
            boolean zF = c0814p2.f(interfaceC0773a03) | c0814p2.h(f);
            Object objI2 = c0814p2.I();
            Object obj6 = objI2;
            if (zF || objI2 == v) {
                com.quizlet.features.practicetest.takingtest.q qVar = new com.quizlet.features.practicetest.takingtest.q(f, interfaceC0773a03, null);
                c0814p2.i0(qVar);
                obj6 = qVar;
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, boolValueOf, (Function2) obj6);
            androidx.lifecycle.B b = androidx.lifecycle.B.a;
            c0814p2.X(1498763815);
            int i5 = i2 & 7168;
            boolean z4 = i5 == 2048;
            Object objI3 = c0814p2.I();
            Object obj7 = objI3;
            if (z4 || objI3 == v) {
                com.quizlet.features.practicetest.takingtest.r rVar = new com.quizlet.features.practicetest.takingtest.r(function12, null);
                c0814p2.i0(rVar);
                obj7 = rVar;
            }
            c0814p2.p(false);
            int i6 = i2 >> 3;
            c0814p2.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p2.j(androidx.lifecycle.compose.g.a);
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) obj7, c0814p2);
            Unit unit = Unit.a;
            c0814p2.X(1667431386);
            boolean zH2 = c0814p2.h(j) | c0814p2.h(w) | c0814p2.f(interfaceC0773a0D);
            Object objI4 = c0814p2.I();
            Object obj8 = objI4;
            if (zH2 || objI4 == v) {
                com.quizlet.features.practicetest.takingtest.p pVar = new com.quizlet.features.practicetest.takingtest.p(interfaceC0773a0D, j, null, w);
                c0814p2.i0(pVar);
                obj8 = pVar;
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit, (Function2) obj8);
            c0814p2.p(false);
            Object[] objArr2 = new Object[0];
            c0814p2.X(1498767800);
            Object objI5 = c0814p2.I();
            Object obj9 = objI5;
            if (objI5 == v) {
                C4392k c4392k = new C4392k(16);
                c0814p2.i0(c4392k);
                obj9 = c4392k;
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) L4.d(objArr2, null, (Function0) obj9, c0814p2, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p2.X(1498770488);
            Object objI6 = c0814p2.I();
            Object obj10 = objI6;
            if (objI6 == v) {
                C4392k c4392k2 = new C4392k(17);
                c0814p2.i0(c4392k2);
                obj10 = c4392k2;
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) L4.d(objArr3, null, (Function0) obj10, c0814p2, 3072, 6);
            c0814p2.X(1498773120);
            Object objI7 = c0814p2.I();
            Object obj11 = objI7;
            if (objI7 == v) {
                InterfaceC0773a0 interfaceC0773a0Z = C0776c.z(null);
                c0814p2.i0(interfaceC0773a0Z);
                obj11 = interfaceC0773a0Z;
            }
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) obj11;
            c0814p2.p(false);
            c0814p2.X(1498775053);
            boolean zH3 = c0814p2.h(w2);
            Object objI8 = c0814p2.I();
            if (zH3 || objI8 == v) {
                com.quizlet.features.practicetest.takingtest.t tVar = new com.quizlet.features.practicetest.takingtest.t(w2, interfaceC0773a06, null);
                c0814p2.i0(tVar);
                obj = tVar;
            } else {
                obj = objI8;
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit, (Function2) obj);
            com.quizlet.features.practicetest.takingtest.data.M m = f.g;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, m != null, c0814p2, 6, 4);
            com.quizlet.assembly.compose.modals.x xVarH2 = Y5.h(true, false, c0814p2, 6, 6);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i7 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            int i8 = i2;
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p2, i7, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "practice_test_taking_test_screen");
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p2.j(b2)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            function02 = function0;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-127094464, new androidx.navigation.compose.p(f, interfaceC0773a04, function0, function1, function2, 2), c0814p2), androidx.compose.runtime.internal.e.e(1345184129, new androidx.navigation.compose.p(f, interfaceC0773a05, function1, interfaceC0773a03, xVarH2, 3), c0814p2), null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(353794251, new com.quizlet.assembly.compose.menu.g(9, f, function1, interfaceC0773a03, interfaceC0773a05, false), c0814p2), c0814p2, 805306806, 184);
            c0814p2.X(-2044716838);
            if (f.h) {
                AbstractC0666j3.a(null, ((com.quizlet.themes.b) c0814p2.j(b2)).K(), DefinitionKt.NO_Float_VALUE, 0L, 0, c0814p2, 0, 29);
            }
            c0814p2.p(false);
            c0814p2.X(-2044712439);
            if (m != null) {
                b(xVarH, m, function1, c0814p2, (i6 & 896) | 8);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(nVar, new C0416v0(C0380d.e(c0814p2).l, 16));
            c0814p2.X(-2044694700);
            boolean zH4 = c0814p2.h(f) | c0814p2.f(interfaceC0773a05) | (i5 == 2048);
            Object objI9 = c0814p2.I();
            if (zH4 || objI9 == v) {
                z = false;
                com.quizlet.features.practicetest.takingtest.h hVar = new com.quizlet.features.practicetest.takingtest.h(f, function1, interfaceC0773a05, false ? 1 : 0);
                c0814p2.i0(hVar);
                obj2 = hVar;
            } else {
                z = false;
                obj2 = objI9;
            }
            c0814p2.p(z);
            f2 = f;
            c(8 | i5, c0814p2, qVarB, xVarH2, (Function0) obj2, function1, f.d);
            C0814p c0814p3 = c0814p2;
            function12 = function1;
            c0814p3.X(-2044693179);
            if (((Boolean) interfaceC0773a04.getValue()).booleanValue()) {
                c0814p3.X(-2044690248);
                interfaceC0773a0 = interfaceC0773a04;
                boolean zF2 = c0814p3.f(interfaceC0773a0);
                Object objI10 = c0814p3.I();
                Object obj12 = objI10;
                if (zF2 || objI10 == v) {
                    com.quizlet.features.practicetest.detail.composables.f fVar = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a0, 1);
                    c0814p3.i0(fVar);
                    obj12 = fVar;
                }
                Function0 function03 = (Function0) obj12;
                c0814p3.p(false);
                c0814p3.X(-2044688306);
                boolean z5 = (i8 & 458752) == 131072;
                Object objI11 = c0814p3.I();
                Object obj13 = objI11;
                if (z5 || objI11 == v) {
                    com.braze.support.u uVar = new com.braze.support.u(25, function02);
                    c0814p3.i0(uVar);
                    obj13 = uVar;
                }
                z2 = false;
                c0814p3.p(false);
                AbstractC3383q2.a(0, c0814p3, null, function03, (Function0) obj13);
            } else {
                interfaceC0773a0 = interfaceC0773a04;
                z2 = false;
            }
            c0814p3.p(z2);
            c0814p3.X(-2044686463);
            if (((Boolean) interfaceC0773a05.getValue()).booleanValue()) {
                c0814p3.X(-2044683202);
                boolean zF3 = c0814p3.f(interfaceC0773a05);
                Object objI12 = c0814p3.I();
                Object obj14 = objI12;
                if (zF3 || objI12 == v) {
                    com.quizlet.features.practicetest.detail.composables.f fVar2 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a05, 2);
                    c0814p3.i0(fVar2);
                    obj14 = fVar2;
                }
                Function0 function04 = (Function0) obj14;
                c0814p3.p(false);
                c0814p3.X(-2044681032);
                boolean z6 = i5 == 2048;
                Object objI13 = c0814p3.I();
                Object obj15 = objI13;
                if (z6 || objI13 == v) {
                    com.quizlet.features.practicetest.detail.m mVar = new com.quizlet.features.practicetest.detail.m(11, function12);
                    c0814p3.i0(mVar);
                    obj15 = mVar;
                }
                z3 = false;
                c0814p3.p(false);
                AbstractC3398u2.a(0, c0814p3, null, function04, (Function0) obj15);
            } else {
                z3 = false;
            }
            c0814p3.p(z3);
            C4416j c4416j = (C4416j) interfaceC0773a06.getValue();
            c0814p3.X(-2044677431);
            if (c4416j != null) {
                c0814p3.X(469806771);
                Object objI14 = c0814p3.I();
                if (objI14 == v) {
                    interfaceC0773a02 = interfaceC0773a06;
                    com.quizlet.features.practicetest.detail.composables.f fVar3 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, i4);
                    c0814p3.i0(fVar3);
                    obj3 = fVar3;
                } else {
                    interfaceC0773a02 = interfaceC0773a06;
                    obj3 = objI14;
                }
                Function0 function05 = (Function0) obj3;
                Object objG = com.google.android.gms.measurement.internal.Z.g(469808691, c0814p3, false);
                Object obj16 = objG;
                if (objG == v) {
                    com.quizlet.features.practicetest.detail.composables.f fVar4 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 4);
                    c0814p3.i0(fVar4);
                    obj16 = fVar4;
                }
                c0814p3.p(false);
                W5.a(R.string.OK, R.string.practice_test_taking_dialog_grading_error_subheader, null, function05, (Function0) obj16, null, Integer.valueOf(R.string.practice_test_taking_dialog_grading_error_header), null, c0814p3, 27648, 164);
                Unit unit2 = Unit.a;
            }
            c0814p3.p(false);
            c0814p3.X(-2044667153);
            boolean zH5 = c0814p3.h(f2) | c0814p3.f(interfaceC0773a0) | ((i8 & 458752) == 131072);
            Object objI15 = c0814p3.I();
            if (zH5 || objI15 == v) {
                r6 = 0;
                com.quizlet.features.practicetest.takingtest.j jVar = new com.quizlet.features.practicetest.takingtest.j(f2, function02, interfaceC0773a0, false ? 1 : 0);
                c0814p3.i0(jVar);
                obj4 = jVar;
            } else {
                r6 = 0;
                obj4 = objI15;
            }
            c0814p3.p(r6);
            androidx.work.impl.t.a(r6, (Function0) obj4, c0814p3, r6, 1);
            c0814p3.p(true);
            c0814p = c0814p3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(f2, w, w2, function12, function2, function02, i, 5);
        }
    }

    public static final void f(com.quizlet.features.practicetest.takingtest.data.F f, Function0 function0, InterfaceC0773a0 interfaceC0773a0) {
        kotlinx.collections.immutable.e eVar = f.d;
        if (eVar == null || !eVar.isEmpty()) {
            Iterator<E> it2 = eVar.iterator();
            while (it2.hasNext()) {
                if (((com.quizlet.features.practicetest.common.data.i) it2.next()).b == com.quizlet.features.practicetest.common.data.j.b) {
                    interfaceC0773a0.setValue(Boolean.TRUE);
                    return;
                }
            }
        }
        function0.invoke();
    }

    public static final void g(com.quizlet.features.practicetest.takingtest.data.F f, Function1 function1, InterfaceC0773a0 interfaceC0773a0) {
        kotlinx.collections.immutable.e eVar = f.d;
        if (eVar == null || !eVar.isEmpty()) {
            Iterator<E> it2 = eVar.iterator();
            while (it2.hasNext()) {
                if (((com.quizlet.features.practicetest.common.data.i) it2.next()).b == com.quizlet.features.practicetest.common.data.j.a) {
                    interfaceC0773a0.setValue(Boolean.TRUE);
                    return;
                }
            }
        }
        function1.invoke(com.quizlet.features.practicetest.takingtest.data.v.a);
    }

    public static final androidx.concurrent.futures.l h(ExecutorC0060p executorC0060p, String debugTag, Function0 block) {
        Intrinsics.checkNotNullParameter(executorC0060p, "<this>");
        Intrinsics.checkNotNullParameter(debugTag, "debugTag");
        Intrinsics.checkNotNullParameter(block, "block");
        androidx.concurrent.futures.l lVarB = com.google.android.gms.internal.mlkit_vision_barcode.Y5.b(new androidx.camera.camera2.internal.T(executorC0060p, debugTag, block, 6));
        Intrinsics.checkNotNullExpressionValue(lVarB, "getFuture { completer ->… }\n        debugTag\n    }");
        return lVarB;
    }

    public static androidx.concurrent.futures.l i(CoroutineContext context, Function2 block) {
        kotlinx.coroutines.D start = kotlinx.coroutines.D.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(start, "start");
        Intrinsics.checkNotNullParameter(block, "block");
        androidx.concurrent.futures.l lVarB = com.google.android.gms.internal.mlkit_vision_barcode.Y5.b(new C1444s(context, block, 0));
        Intrinsics.checkNotNullExpressionValue(lVarB, "getFuture { completer ->…owable)\n        }\n    }\n}");
        return lVarB;
    }

    public static void j(org.jsoup.select.n nVar, org.jsoup.nodes.n nVar2) {
        org.jsoup.helper.b.g(nVar2);
        org.jsoup.nodes.n nVarQ = nVar2;
        int i = 0;
        while (nVarQ != null) {
            org.jsoup.nodes.n nVar3 = nVarQ.a;
            int iG = nVar3 != null ? nVar3.g() : 0;
            org.jsoup.nodes.n nVarQ2 = nVarQ.q();
            nVar.d(nVarQ, i);
            if (nVar3 != null && nVarQ.a == null) {
                if (iG == nVar3.g()) {
                    nVarQ = (org.jsoup.nodes.n) nVar3.m().get(nVarQ.b);
                } else if (nVarQ2 == null) {
                    i--;
                    nVarQ = nVar3;
                } else {
                    nVarQ = nVarQ2;
                }
            }
            if (nVarQ.g() > 0) {
                nVarQ = (org.jsoup.nodes.n) nVarQ.m().get(0);
                i++;
            } else {
                while (nVarQ.q() == null && i > 0) {
                    nVar.i(nVarQ, i);
                    nVarQ = nVarQ.a;
                    i--;
                }
                nVar.i(nVarQ, i);
                if (nVarQ == nVar2) {
                    return;
                } else {
                    nVarQ = nVarQ.q();
                }
            }
        }
    }
}
