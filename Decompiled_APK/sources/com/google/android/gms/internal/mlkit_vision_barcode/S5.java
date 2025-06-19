package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.AdvertisementType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class S5 {
    public static final void a(Function1 function1, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1146418631);
        int i2 = i | (c0814p2.h(function1) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Object obj = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(-535595849);
            Object objI = c0814p2.I();
            if (objI == obj) {
                objI = new com.quizlet.features.emailconfirmation.ui.composables.c(17);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p2, 3072, 6);
            c0814p2.X(-535594205);
            Object objI2 = c0814p2.I();
            if (objI2 == obj) {
                objI2 = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI2);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI2;
            c0814p2.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "CourseInputTestTag");
            c0814p2.X(-535589056);
            Object objI3 = c0814p2.I();
            if (objI3 == obj) {
                objI3 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 5);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarW = androidx.compose.ui.focus.a.w(qVarG, (Function1) objI3);
            String str = (String) interfaceC0773a0.getValue();
            String strD = AbstractC3106b5.d(c0814p2, R.string.search_course);
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarH = com.quizlet.ui.resources.icons.d.H(c0814p2);
            c0814p2.X(-535582319);
            boolean zF = ((i2 & 14) == 4) | c0814p2.f(interfaceC0773a0);
            Object objI4 = c0814p2.I();
            if (zF || objI4 == obj) {
                objI4 = new com.quizlet.features.flashcards.settings.ui.e(3, interfaceC0773a0, function1);
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.a(str, qVarW, (Function1) objI4, null, strD, 0, 0, 255, null, 0, 0, null, null, false, false, bVarH, 0, null, DefinitionKt.NO_Float_VALUE, null, null, androidx.compose.runtime.internal.e.e(851859276, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.j(interfaceC0773a0, function0, interfaceC0773a02), c0814p2), c0814p, 100663296, 0, 384, 4128488);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 26, function1, qVar, function0);
        }
    }

    public static final void b(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q state, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        Function1 function12;
        int i4;
        Function1 function13;
        androidx.compose.animation.core.K0 k0;
        Function1 function14;
        androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-349861874);
        int i5 = i | (c0814p.f(state) ? 4 : 2);
        int i6 = i2 & 2;
        if (i6 != 0) {
            i3 = i5 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i5 | (c0814p.f(qVar2) ? 32 : 16);
        }
        int i7 = i2 & 4;
        if (i7 != 0) {
            i4 = i3 | 384;
            function12 = function1;
        } else {
            function12 = function1;
            i4 = i3 | (c0814p.h(function12) ? 256 : 128);
        }
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i6 != 0) {
                qVar2 = nVar;
            }
            androidx.compose.runtime.V v = C0804k.a;
            if (i7 != 0) {
                c0814p.X(354219884);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new C4237k(18);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function13 = (Function1) objI;
            } else {
                function13 = function12;
            }
            androidx.compose.foundation.lazy.A a = androidx.compose.foundation.lazy.D.a(0, c0814p, 3);
            c0814p.X(354222695);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new androidx.compose.ui.focus.p();
                c0814p.i0(objI2);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI2;
            Object objG = com.google.android.gms.measurement.internal.Z.g(354224647, c0814p, false);
            if (objG == v) {
                objG = new androidx.compose.ui.focus.p();
                c0814p.i0(objG);
            }
            androidx.compose.ui.focus.p pVar2 = (androidx.compose.ui.focus.p) objG;
            c0814p.p(false);
            boolean z = state instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.o;
            boolean z2 = (state instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p) && ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p) state).e;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar2, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarA = androidx.compose.animation.H.a(AbstractC0382e.y(qVarC, f, f, f, DefinitionKt.NO_Float_VALUE, 8), null, 3);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarA);
            InterfaceC0915k.D0.getClass();
            androidx.compose.ui.q qVar4 = qVar2;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strA = state.a();
            mVar.s();
            androidx.compose.ui.q qVarK = androidx.compose.ui.focus.a.k(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), pVar2);
            c0814p.X(-1486130613);
            int i9 = i4 & 896;
            boolean zG = c0814p.g(z2) | (i9 == 256);
            Object objI3 = c0814p.I();
            if (zG || objI3 == v) {
                objI3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.i(function13, z2);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarW = androidx.compose.ui.focus.a.w(qVarK, (Function1) objI3);
            c0814p.X(-1486141586);
            boolean z3 = i9 == 256;
            Object objI4 = c0814p.I();
            if (z3 || objI4 == v) {
                objI4 = new androidx.navigation.compose.B(28, function13);
                c0814p.i0(objI4);
            }
            Function1 function15 = (Function1) objI4;
            c0814p.p(false);
            c0814p.X(-1486123551);
            boolean z4 = i9 == 256;
            int i10 = i4;
            Object objI5 = c0814p.I();
            if (z4 || objI5 == v) {
                objI5 = new com.quizlet.facebook.a(29, function13);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            boolean z5 = z2;
            c(0, c0814p, qVarW, strA, (Function0) objI5, function15);
            Boolean boolValueOf = Boolean.valueOf(z5);
            c0814p.X(-1486118756);
            boolean zG2 = c0814p.g(z5);
            Object objI6 = c0814p.I();
            if (zG2 || objI6 == v) {
                k0 = null;
                objI6 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.k(z5, pVar2, null);
                c0814p.i0(objI6);
            } else {
                k0 = null;
            }
            c0814p.p(false);
            C0776c.f(c0814p, boolValueOf, (Function2) objI6);
            Function1 function16 = function13;
            androidx.compose.animation.E.f(z, null, androidx.compose.animation.V.c(k0, 3).a(androidx.compose.animation.V.b(k0, 15)), androidx.compose.animation.V.f(k0, 15).a(androidx.compose.animation.V.d(k0, 3)), null, androidx.compose.runtime.internal.e.e(-300490752, new com.quizlet.assembly.compose.input.m(16, function13, pVar), c0814p), c0814p, 1600518, 18);
            c0814p.X(-1486088050);
            if (state.c() && !state.getResults().isEmpty()) {
                mVar.u();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
                mVar.u();
                e(state.a(), state instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f2, 5), c0814p, 0);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarA2 = androidx.compose.animation.H.a(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), null, 3);
            androidx.compose.foundation.lazy.A a2 = androidx.compose.foundation.lazy.D.a(0, c0814p, 3);
            mVar.s();
            mVar.u();
            androidx.compose.foundation.layout.A0 a0E = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, f, 5);
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f);
            c0814p.X(-1486058570);
            boolean zF = c0814p.f(a) | ((i10 & 14) == 4) | (i9 == 256);
            Object objI7 = c0814p.I();
            if (zF || objI7 == v) {
                function14 = function16;
                objI7 = new androidx.lifecycle.compose.d(state, a, function14, 9);
                c0814p.i0(objI7);
            } else {
                function14 = function16;
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarA2, a2, a0E, c0392jG, null, null, false, (Function1) objI7, c0814p, 0, AdvertisementType.BRANDED_ON_DEMAND_MID_ROLL);
            c0814p = c0814p;
            c0814p.p(true);
            function12 = function14;
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, i2, 14, state, qVar3, function12);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function0 function0, Function1 function1) {
        androidx.compose.ui.graphics.painter.b bVarH;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1616523095);
        int i2 = i | (c0814p2.h(function1) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(-2054388665);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = C0776c.z("");
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-2054386966, c0814p2, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG;
            c0814p2.p(false);
            if (str != null && str.length() != 0) {
                interfaceC0773a0.setValue(str);
            }
            c0814p2.X(-2054382949);
            if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                com.quizlet.themes.e.a(c0814p2).a.getClass();
                bVarH = com.quizlet.ui.resources.icons.d.H(c0814p2);
            } else {
                bVarH = null;
            }
            androidx.compose.ui.graphics.painter.b bVar = bVarH;
            c0814p2.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "SchoolInputTestTag");
            c0814p2.X(-2054376288);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 4);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarW = androidx.compose.ui.focus.a.w(qVarG, (Function1) objI2);
            String str2 = (String) interfaceC0773a0.getValue();
            String strD = AbstractC3106b5.d(c0814p2, R.string.search_school);
            c0814p2.X(-2054369768);
            boolean z = (i2 & 14) == 4;
            Object objI3 = c0814p2.I();
            if (z || objI3 == v) {
                objI3 = new com.quizlet.features.flashcards.settings.ui.e(4, interfaceC0773a0, function1);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.a(str2, qVarW, (Function1) objI3, null, strD, 0, 0, 255, null, 0, 0, null, null, false, false, bVar, 0, null, DefinitionKt.NO_Float_VALUE, null, null, androidx.compose.runtime.internal.e.e(890541796, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.j(function0, interfaceC0773a02, interfaceC0773a0), c0814p2), c0814p, 100663296, 0, 384, 4128488);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) function1, (Object) qVar, (Object) str, function0, i, 12);
        }
    }

    public static final void d(float f, androidx.compose.ui.q qVar, androidx.compose.ui.graphics.I i, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.graphics.I i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-548874658);
        int i4 = (c0814p.c(f) ? 4 : 2) | i2;
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(qVar) ? 32 : 16;
        }
        if (((i4 | 128) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            i3 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                c0814p.X(-2073589074);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                kotlinx.collections.immutable.e colors = AbstractC3409x1.h(new C0861v(((com.quizlet.themes.b) c0814p.j(b)).b.h()), new C0861v(((com.quizlet.themes.b) c0814p.j(b)).S), new C0861v(((com.quizlet.themes.b) c0814p.j(b)).b.h()));
                Intrinsics.checkNotNullParameter(colors, "colors");
                c0814p.X(1886611077);
                androidx.compose.animation.core.J jG = AbstractC0240f.g(AbstractC0240f.p("", c0814p, 0), DefinitionKt.NO_Float_VALUE, 1500.0f, AbstractC0240f.o(AbstractC0240f.r(1500, 0, null, 6), 4), "", c0814p, 29112, 0);
                i3 = new androidx.compose.ui.graphics.I(colors, null, 0L, Q4.c(((Number) ((androidx.compose.runtime.L0) jG.d).getValue()).floatValue(), ((Number) ((androidx.compose.runtime.L0) jG.d).getValue()).floatValue()));
                c0814p.p(false);
                c0814p.p(false);
            } else {
                c0814p.Q();
                i3 = i;
            }
            c0814p.q();
            com.quizlet.themes.m.g.e();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(AbstractC0460p.e(qVar, i3, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.f), 4), f));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.a(f, qVar, i3, i2);
        }
    }

    public static final void e(String str, boolean z, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.graphics.painter.b bVarM;
        String strC;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1720466969);
        if ((((c0814p.f(str) ? 4 : 2) | i | (c0814p.g(z) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1959731344);
            if (z) {
                c0814p.X(-1986692327);
                com.quizlet.themes.e.a(c0814p).a.getClass();
                c0814p.X(748572206);
                bVarM = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_location, c0814p, 0, false, false);
            } else {
                c0814p.X(-1986650570);
                com.quizlet.themes.e.a(c0814p).a.getClass();
                bVarM = com.quizlet.ui.resources.icons.d.M(c0814p);
                c0814p.p(false);
            }
            c0814p.p(false);
            c0814p.X(-553996355);
            if (z) {
                strC = com.google.android.gms.measurement.internal.Z.h(c0814p, -1903739431, R.string.school_suggestion, c0814p, false);
            } else {
                c0814p.X(-1903683476);
                strC = AbstractC3106b5.c(R.string.course_suggestions, new Object[]{str}, c0814p);
                c0814p.p(false);
            }
            String str2 = strC;
            c0814p.p(false);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.D1.a(bVarM, null, null, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), c0814p, 48, 4);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            androidx.compose.material3.Q4.b(str2, AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.textbook.ui.composables.h(str, z, qVar, i);
        }
    }

    public static final long f(double d) {
        return i(4294967296L, (float) d);
    }

    public static final long g(int i) {
        return i(4294967296L, i);
    }

    public static final boolean h(long j) {
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        return (j & 1095216660480L) == 0;
    }

    public static final long i(long j, float f) {
        long jFloatToIntBits = j | (Float.floatToIntBits(f) & 4294967295L);
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        return jFloatToIntBits;
    }
}
