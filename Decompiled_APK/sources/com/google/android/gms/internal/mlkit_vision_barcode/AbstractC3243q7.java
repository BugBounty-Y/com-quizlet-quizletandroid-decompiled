package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.material3.AbstractC0590b0;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.data.model.ReviewSheetInfo;
import com.quizlet.features.folders.composables.C4257m;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.compose.C4815h;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.q7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3243q7 {
    public static final void a(com.quizlet.features.notes.detail.states.g gVar, Function1 function1, androidx.compose.ui.q qVar, Function2 function2, androidx.compose.foundation.layout.z0 z0Var, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function12;
        C0814p c0814p;
        Function2 function22;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-771574661);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(gVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(z0Var) ? 16384 : 8192;
        }
        if ((i2 & 8339) == 8338 && c0814p2.x()) {
            c0814p2.Q();
            function22 = function2;
            function12 = function1;
            c0814p = c0814p2;
        } else {
            Object obj = C0804k.a;
            c0814p2.X(1933446999);
            Object objI = c0814p2.I();
            if (objI == obj) {
                objI = new androidx.navigation.compose.x(13);
                c0814p2.i0(objI);
            }
            Function2 function23 = (Function2) objI;
            c0814p2.p(false);
            Object obj2 = gVar.a.d;
            c0814p2.X(1933449917);
            boolean zF = c0814p2.f(obj2);
            Object objI2 = c0814p2.I();
            NotesToValueInfo notesToValueInfo = gVar.a;
            if (zF || objI2 == obj) {
                objI2 = notesToValueInfo.d;
                c0814p2.i0(objI2);
            }
            OutlineMarkdownInfo outlineMarkdownInfo = (OutlineMarkdownInfo) objI2;
            c0814p2.p(false);
            Object obj3 = notesToValueInfo.e;
            c0814p2.X(1933453333);
            boolean zF2 = c0814p2.f(obj3);
            Object objI3 = c0814p2.I();
            if (zF2 || objI3 == obj) {
                objI3 = notesToValueInfo.e;
                c0814p2.i0(objI3);
            }
            ReviewSheetInfo reviewSheetInfo = (ReviewSheetInfo) objI3;
            c0814p2.p(false);
            c0814p2.X(1933456201);
            Object obj4 = notesToValueInfo.g;
            boolean zF3 = c0814p2.f(obj4);
            Object objI4 = c0814p2.I();
            if (zF3 || objI4 == obj) {
                c0814p2.i0(obj4);
            } else {
                obj4 = objI4;
            }
            EssayInfo essayInfo = (EssayInfo) obj4;
            c0814p2.p(false);
            c0814p2.X(1933458867);
            Object obj5 = notesToValueInfo.f;
            boolean zF4 = c0814p2.f(obj5);
            Object objI5 = c0814p2.I();
            if (zF4 || objI5 == obj) {
                c0814p2.i0(obj5);
            } else {
                obj5 = objI5;
            }
            FlashcardsInfo flashcardsInfo = (FlashcardsInfo) obj5;
            c0814p2.p(false);
            androidx.compose.ui.q qVarT = AbstractC0382e.t(qVar, Q5.a(z0Var));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarT);
            InterfaceC0915k.D0.getClass();
            Function0 function0 = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(function0);
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
            function12 = function1;
            kotlinx.collections.immutable.e eVarH = AbstractC3409x1.h(new C4815h(AbstractC3106b5.d(c0814p2, R.string.magic_notes_tab_bar_outline), null, androidx.compose.runtime.internal.e.e(-639560554, new C4257m(gVar, outlineMarkdownInfo, function1, flashcardsInfo, essayInfo, z0Var, 1), c0814p2)), new C4815h(AbstractC3106b5.d(c0814p2, R.string.magic_notes_tab_bar_quick_reference), null, androidx.compose.runtime.internal.e.e(1499279319, new com.quizlet.assembly.compose.menu.l(reviewSheetInfo, z0Var, function12, 15), c0814p2)));
            c0814p2.X(-1313311208);
            boolean zH = c0814p2.h(eVarH);
            Object objI6 = c0814p2.I();
            if (zH || objI6 == obj) {
                objI6 = new com.quizlet.features.home.composables.sections.a(eVarH, 1);
                c0814p2.i0(objI6);
            }
            c0814p2.p(false);
            C0466e c0466eB = androidx.compose.foundation.pager.I.b(0, (Function0) objI6, c0814p2, 0, 3);
            c0814p = c0814p2;
            C5.b(eVarH, c0466eB, null, c0814p, 8, 4);
            D5.a(eVarH, c0466eB, null, 0L, false, null, c0814p, 24584, 44);
            c0814p.p(true);
            function22 = function23;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p((Object) gVar, function12, (Object) qVar, (InterfaceC4938g) function22, (Object) z0Var, i, 7);
        }
    }

    public static final void b(final Function0 function0, final Function1 function1, final Function1 function12, final Function1 function13, final Function1 function14, final Function1 function15, final Function2 function2, final Function0 function02, final Function2 function22, final Function2 function23, final Function0 function03, final Function0 function04, com.quizlet.features.notes.detail.viewmodels.v vVar, com.quizlet.features.infra.folder.menu.viewmodel.n nVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        Object obj;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar2;
        com.quizlet.features.notes.detail.viewmodels.v vVar2;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar3;
        Object obj2;
        androidx.compose.material3.O3 o3;
        kotlinx.coroutines.flow.d0 d0Var;
        com.quizlet.assembly.compose.modals.x xVar;
        boolean z;
        InterfaceC0773a0 interfaceC0773a0;
        com.quizlet.assembly.compose.toasts.g gVar;
        com.quizlet.assembly.compose.modals.x xVar2;
        com.quizlet.assembly.compose.modals.x xVar3;
        InterfaceC0773a0 interfaceC0773a02;
        InterfaceC0773a0 interfaceC0773a03;
        InterfaceC0773a0 interfaceC0773a04;
        InterfaceC0773a0 interfaceC0773a05;
        androidx.compose.material3.O3 o32;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar4;
        com.quizlet.features.notes.detail.viewmodels.v vVar3;
        boolean z2;
        final com.quizlet.features.notes.detail.viewmodels.v vVar4;
        final com.quizlet.features.infra.folder.menu.viewmodel.n nVar5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1081954487);
        int i3 = i | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function12) ? 256 : 128) | (c0814p.h(function13) ? 2048 : 1024) | (c0814p.h(function14) ? 16384 : 8192) | (c0814p.h(function15) ? 131072 : 65536) | (c0814p.h(function23) ? 536870912 : 268435456);
        if ((306783379 & i3) == 306783378 && c0814p.x()) {
            c0814p.Q();
            vVar4 = vVar;
            nVar5 = nVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            Object obj3 = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                i2 = i3;
                obj = obj3;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.notes.detail.viewmodels.v.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.notes.detail.viewmodels.v vVar5 = (com.quizlet.features.notes.detail.viewmodels.v) w0VarE;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A2 = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A2 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC2 = AbstractC3405w1.c(c0A2, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.infra.folder.menu.viewmodel.a.class, c0A2, null, fVarC2, c0A2 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A2).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                nVar2 = (com.quizlet.features.infra.folder.menu.viewmodel.n) objE;
                vVar2 = vVar5;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                i2 = i3;
                obj = obj3;
                vVar2 = vVar;
            }
            c0814p.q();
            c0814p.X(928603136);
            Object objI = c0814p.I();
            if (objI == obj) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(928605344, c0814p, false);
            if (objG == obj) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a07 = (InterfaceC0773a0) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(928607648, c0814p, false);
            if (objG2 == obj) {
                objG2 = C0776c.z(Boolean.FALSE);
                c0814p.i0(objG2);
            }
            InterfaceC0773a0 interfaceC0773a08 = (InterfaceC0773a0) objG2;
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(vVar2.q, c0814p);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(vVar2.s, c0814p);
            com.quizlet.assembly.compose.toasts.g gVarD = AbstractC3667l6.d(c0814p);
            com.quizlet.assembly.compose.modals.x xVarH = com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(true, false, c0814p, 6, 6);
            c0814p.X(928617067);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = C0776c.z(null);
                c0814p.i0(objI2);
            }
            InterfaceC0773a0 interfaceC0773a09 = (InterfaceC0773a0) objI2;
            c0814p.p(false);
            com.quizlet.assembly.compose.modals.x xVarH2 = com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(false, false, c0814p, 0, 7);
            c0814p.X(928621534);
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = new androidx.compose.material3.O3();
                c0814p.i0(objI3);
            }
            androidx.compose.material3.O3 o33 = (androidx.compose.material3.O3) objI3;
            c0814p.p(false);
            androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
            c0814p.X(928626847);
            boolean zH = c0814p.h(vVar2);
            Object objI4 = c0814p.I();
            if (zH || objI4 == obj) {
                objI4 = new com.quizlet.features.folders.composables.J(vVar2, 4);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            androidx.activity.compose.o oVarF = androidx.work.P.f(bVar, (Function1) objI4, c0814p);
            kotlinx.coroutines.flow.d0 d0Var2 = vVar2.r;
            c0814p.X(928634734);
            int i5 = i2;
            boolean zH2 = ((i2 & 7168) == 2048) | c0814p.h(gVarD) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256) | ((i5 & 57344) == 16384) | ((i5 & 458752) == 131072) | ((i5 & 1879048192) == 536870912) | c0814p.h(oVarF);
            Object objI5 = c0814p.I();
            if (zH2 || objI5 == obj) {
                nVar3 = nVar2;
                obj2 = obj;
                o3 = o33;
                d0Var = d0Var2;
                xVar = xVarH;
                z = false;
                com.quizlet.features.notes.detail.composables.magicnotesdetail.C c = new com.quizlet.features.notes.detail.composables.magicnotesdetail.C(function0, function02, function03, function04, gVarD, function1, function12, function13, function14, function15, function22, function23, function2, oVarF, interfaceC0773a06, null);
                interfaceC0773a0 = interfaceC0773a06;
                c0814p.i0(c);
                objI5 = c;
            } else {
                nVar3 = nVar2;
                obj2 = obj;
                o3 = o33;
                d0Var = d0Var2;
                interfaceC0773a0 = interfaceC0773a06;
                xVar = xVarH;
                z = false;
            }
            c0814p.p(z);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI5, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            kotlinx.coroutines.flow.d0 d0Var3 = d0Var;
            boolean zH3 = c0814p.h(j) | c0814p.h(d0Var3) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI6 = c0814p.I();
            if (zH3 || objI6 == obj2) {
                objI6 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.v(interfaceC0773a0D, j, null, d0Var3);
                c0814p.i0(objI6);
            }
            c0814p.p(z);
            C0776c.f(c0814p, unit, (Function2) objI6);
            c0814p.p(z);
            kotlinx.coroutines.flow.d0 d0Var4 = vVar2.t;
            c0814p.X(928679290);
            com.quizlet.assembly.compose.modals.x xVar4 = xVar;
            boolean zF = c0814p.f(interfaceC0773a0M) | c0814p.h(xVarH2) | c0814p.h(xVar4);
            Object objI7 = c0814p.I();
            if (zF || objI7 == obj2) {
                gVar = gVarD;
                objI7 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.D(xVarH2, xVar4, interfaceC0773a08, interfaceC0773a0M, interfaceC0773a09, interfaceC0773a07, null);
                xVar2 = xVarH2;
                xVar3 = xVar4;
                interfaceC0773a02 = interfaceC0773a08;
                interfaceC0773a03 = interfaceC0773a0M;
                interfaceC0773a04 = interfaceC0773a09;
                interfaceC0773a05 = interfaceC0773a07;
                c0814p.i0(objI7);
            } else {
                interfaceC0773a03 = interfaceC0773a0M;
                xVar3 = xVar4;
                gVar = gVarD;
                interfaceC0773a04 = interfaceC0773a09;
                interfaceC0773a05 = interfaceC0773a07;
                xVar2 = xVarH2;
                interfaceC0773a02 = interfaceC0773a08;
            }
            c0814p.p(z);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI7, c0814p);
            c0814p.X(1667431386);
            boolean zH4 = c0814p.h(j2) | c0814p.h(d0Var4) | c0814p.f(b) | c0814p.f(interfaceC0773a0D2);
            InterfaceC0773a0 interfaceC0773a010 = interfaceC0773a02;
            Object objI8 = c0814p.I();
            if (zH4 || objI8 == obj2) {
                objI8 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.x(interfaceC0773a0D2, j2, null, d0Var4);
                c0814p.i0(objI8);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI8);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var5 = vVar2.u;
            c0814p.X(928702294);
            com.quizlet.features.infra.folder.menu.viewmodel.n nVar6 = nVar3;
            boolean zH5 = c0814p.h(nVar6);
            Object objI9 = c0814p.I();
            if (zH5 || objI9 == obj2) {
                objI9 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.E(nVar6, null);
                c0814p.i0(objI9);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j3 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D3 = C0776c.D((Function2) objI9, c0814p);
            c0814p.X(1667431386);
            boolean zH6 = c0814p.h(j3) | c0814p.h(d0Var5) | c0814p.f(b) | c0814p.f(interfaceC0773a0D3);
            InterfaceC0773a0 interfaceC0773a011 = interfaceC0773a04;
            Object objI10 = c0814p.I();
            if (zH6 || objI10 == obj2) {
                objI10 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.z(interfaceC0773a0D3, j3, null, d0Var5);
                c0814p.i0(objI10);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI10);
            c0814p.p(false);
            InterfaceC4992i interfaceC4992iU = nVar6.u();
            c0814p.X(928719436);
            Object objI11 = c0814p.I();
            if (objI11 == obj2) {
                o32 = o3;
                objI11 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.F(o32, null);
                c0814p.i0(objI11);
            } else {
                o32 = o3;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j4 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D4 = C0776c.D((Function2) objI11, c0814p);
            c0814p.X(1667431386);
            boolean zH7 = c0814p.h(j4) | c0814p.h(interfaceC4992iU) | c0814p.f(b) | c0814p.f(interfaceC0773a0D4);
            Object objI12 = c0814p.I();
            if (zH7 || objI12 == obj2) {
                objI12 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.B(interfaceC0773a0D4, j4, null, interfaceC4992iU);
                c0814p.i0(objI12);
            }
            c0814p.p(false);
            com.quizlet.features.notes.detail.states.h hVar = (com.quizlet.features.notes.detail.states.h) AbstractC4178x.k(unit, (Function2) objI12, c0814p, false, interfaceC0773a03);
            c0814p.X(928724270);
            boolean zH8 = c0814p.h(nVar6);
            Object objI13 = c0814p.I();
            if (zH8 || objI13 == obj2) {
                objI13 = new com.quizlet.explanations.textbook.ui.f(1, nVar6, com.quizlet.features.infra.folder.menu.viewmodel.n.class, "onAddToFolderUndoClick", "onAddToFolderUndoClick(Lcom/quizlet/data/interactor/folderstudymaterial/FolderManipulateAction;)V", 0, 29);
                nVar4 = nVar6;
                c0814p.i0(objI13);
            } else {
                nVar4 = nVar6;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI13;
            c0814p.p(false);
            com.quizlet.features.notes.detail.menu.n nVar7 = (com.quizlet.features.notes.detail.menu.n) interfaceC0773a0M2.getValue();
            c0814p.X(928729176);
            boolean zH9 = c0814p.h(vVar2);
            Object objI14 = c0814p.I();
            if (zH9 || objI14 == obj2) {
                vVar3 = vVar2;
                objI14 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, vVar3, com.quizlet.features.notes.detail.viewmodels.v.class, "onEventReceived", "onEventReceived(Lcom/quizlet/features/notes/common/events/MagicNotesEvent;)V", 0, 0);
                c0814p.i0(objI14);
            } else {
                vVar3 = vVar2;
            }
            c0814p.p(false);
            boolean zBooleanValue = ((Boolean) interfaceC0773a05.getValue()).booleanValue();
            boolean zBooleanValue2 = ((Boolean) interfaceC0773a010.getValue()).booleanValue();
            com.quizlet.features.notes.data.e eVar = (com.quizlet.features.notes.data.e) interfaceC0773a011.getValue();
            Function1 function16 = (Function1) fVar;
            Function1 function17 = (Function1) ((kotlin.reflect.f) objI14);
            c0814p.X(928735872);
            Object objI15 = c0814p.I();
            if (objI15 == obj2) {
                objI15 = new androidx.navigation.compose.z(interfaceC0773a05, 17);
                c0814p.i0(objI15);
            }
            c0814p.p(false);
            com.quizlet.features.notes.detail.viewmodels.v vVar6 = vVar3;
            Object obj4 = obj2;
            c(hVar, function16, nVar7, o32, function17, gVar, xVar3, zBooleanValue, (Function0) objI15, zBooleanValue2, eVar, xVar2, c0814p, 103025664);
            c0814p = c0814p;
            c0814p.X(928741703);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                c0814p.X(928749189);
                Object objI16 = c0814p.I();
                if (objI16 == obj4) {
                    objI16 = new androidx.navigation.compose.z(interfaceC0773a0, 18);
                    c0814p.i0(objI16);
                }
                z2 = false;
                c0814p.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.W5.a(R.string.OK, R.string.magic_notes_detail_overflow_menu_error_description, null, null, (Function0) objI16, null, null, null, c0814p, 24576, 236);
                c0814p = c0814p;
            } else {
                z2 = false;
            }
            c0814p.p(z2);
            c0814p.X(928752074);
            boolean zH10 = c0814p.h(vVar6);
            Object objI17 = c0814p.I();
            if (zH10 || objI17 == obj4) {
                objI17 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.H(vVar6, null);
                c0814p.i0(objI17);
            }
            c0814p.p(z2);
            C0776c.f(c0814p, unit, (Function2) objI17);
            vVar4 = vVar6;
            nVar5 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(function1, function12, function13, function14, function15, function2, function02, function22, function23, function03, function04, vVar4, nVar5, i) { // from class: com.quizlet.features.notes.detail.composables.magicnotesdetail.r
                public final /* synthetic */ Function1 b;
                public final /* synthetic */ Function1 c;
                public final /* synthetic */ Function1 d;
                public final /* synthetic */ Function1 e;
                public final /* synthetic */ Function1 f;
                public final /* synthetic */ Function2 g;
                public final /* synthetic */ Function0 h;
                public final /* synthetic */ Function2 i;
                public final /* synthetic */ Function2 j;
                public final /* synthetic */ Function0 k;
                public final /* synthetic */ Function0 l;
                public final /* synthetic */ com.quizlet.features.notes.detail.viewmodels.v m;
                public final /* synthetic */ com.quizlet.features.infra.folder.menu.viewmodel.n n;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj5, Object obj6) {
                    ((Integer) obj6).getClass();
                    int iH = C0776c.H(114819079);
                    com.quizlet.features.notes.detail.viewmodels.v vVar7 = this.m;
                    com.quizlet.features.infra.folder.menu.viewmodel.n nVar8 = this.n;
                    AbstractC3243q7.b(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, vVar7, nVar8, (InterfaceC0806l) obj5, iH);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x02d8  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x02db  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x02de  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x02e4  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x02e9  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x02f7  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02f9  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0302  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0319  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x0344  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x0370  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x03bf  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x03c1  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x03ca  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(com.quizlet.features.notes.detail.states.h r40, final kotlin.jvm.functions.Function1 r41, final com.quizlet.features.notes.detail.menu.n r42, final androidx.compose.material3.O3 r43, kotlin.jvm.functions.Function1 r44, final com.quizlet.assembly.compose.toasts.g r45, final com.quizlet.assembly.compose.modals.x r46, final boolean r47, kotlin.jvm.functions.Function0 r48, final boolean r49, final com.quizlet.features.notes.data.e r50, final com.quizlet.assembly.compose.modals.x r51, androidx.compose.runtime.InterfaceC0806l r52, final int r53) {
        /*
            Method dump skipped, instructions count: 1037
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7.c(com.quizlet.features.notes.detail.states.h, kotlin.jvm.functions.Function1, com.quizlet.features.notes.detail.menu.n, androidx.compose.material3.O3, kotlin.jvm.functions.Function1, com.quizlet.assembly.compose.toasts.g, com.quizlet.assembly.compose.modals.x, boolean, kotlin.jvm.functions.Function0, boolean, com.quizlet.features.notes.data.e, com.quizlet.assembly.compose.modals.x, androidx.compose.runtime.l, int):void");
    }

    public static final void d(final NotesToValueInfo notesToValueInfo, final boolean z, final Function0 function0, final Function0 function02, final Function0 function03, final Function0 function04, final Function1 function1, final Function0 function05, final com.quizlet.data.repository.achievements.h hVar, final com.quizlet.features.notes.detail.menu.n nVar, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1641488240);
        int i2 = i | (c0814p2.h(notesToValueInfo) ? 4 : 2) | (c0814p2.g(z) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.h(function02) ? 2048 : 1024) | (c0814p2.h(function03) ? 16384 : 8192) | (c0814p2.h(function04) ? 131072 : 65536) | (c0814p2.h(function1) ? 1048576 : 524288) | (c0814p2.h(function05) ? 8388608 : 4194304) | (c0814p2.f(hVar) ? 67108864 : 33554432) | (c0814p2.f(nVar) ? 536870912 : 268435456);
        if ((i2 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            float f = com.quizlet.themes.m.L;
            float f2 = androidx.compose.material3.W4.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p2.j(b)).b.g();
            long jG2 = ((com.quizlet.themes.b) c0814p2.j(b)).b.g();
            long j = C0861v.g;
            androidx.compose.material3.Z z2 = (androidx.compose.material3.Z) c0814p2.j(AbstractC0590b0.a);
            androidx.compose.material3.V4 v4 = z2.P;
            if (v4 == null) {
                float f3 = androidx.compose.material3.tokens.B.a;
                v4 = new androidx.compose.material3.V4(AbstractC0590b0.c(z2, 35), AbstractC0590b0.c(z2, androidx.compose.material3.tokens.D.e), AbstractC0590b0.c(z2, androidx.compose.material3.tokens.B.d), AbstractC0590b0.c(z2, androidx.compose.material3.tokens.B.b), AbstractC0590b0.c(z2, androidx.compose.material3.tokens.B.e));
                z2.P = v4;
            }
            androidx.compose.material3.D.b(androidx.compose.runtime.internal.e.e(-658883241, new androidx.navigation.compose.o(24, notesToValueInfo, function04), c0814p2), null, null, null, DefinitionKt.NO_Float_VALUE, f, null, v4.a(jG, jG2, j, j, j), hVar, c0814p2, (i2 & 234881024) | 6, 94);
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            c0814p = c0814p2;
            AbstractC3691o6.c(null, null, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), 0L, com.quizlet.ui.resources.icons.d.m(c0814p2), function0, androidx.compose.runtime.internal.e.e(1958703310, new com.quizlet.features.notes.detail.composables.magicnotesdetail.J(z, notesToValueInfo, function02, nVar, function03, function1, function05), c0814p2), null, c0814p, ((i2 << 9) & 458752) | 1572864, 139);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(z, function0, function02, function03, function04, function1, function05, hVar, nVar, i) { // from class: com.quizlet.features.notes.detail.composables.magicnotesdetail.q
                public final /* synthetic */ boolean b;
                public final /* synthetic */ Function0 c;
                public final /* synthetic */ Function0 d;
                public final /* synthetic */ Function0 e;
                public final /* synthetic */ Function0 f;
                public final /* synthetic */ Function1 g;
                public final /* synthetic */ Function0 h;
                public final /* synthetic */ com.quizlet.data.repository.achievements.h i;
                public final /* synthetic */ com.quizlet.features.notes.detail.menu.n j;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    com.quizlet.data.repository.achievements.h hVar2 = this.i;
                    com.quizlet.features.notes.detail.menu.n nVar2 = this.j;
                    AbstractC3243q7.d(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, hVar2, nVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final androidx.glance.p e(androidx.glance.p pVar, float f) {
        return pVar.d(new androidx.glance.appwidget.A(new androidx.glance.unit.c(f)));
    }

    public static final Object f(io.ktor.utils.io.k kVar, kotlin.coroutines.jvm.internal.i iVar) throws Throwable {
        Object objG;
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        Throwable thC = kVar.c();
        if (thC != null) {
            throw thC;
        }
        kotlinx.io.a aVarI = kVar.i();
        Intrinsics.checkNotNullParameter(aVarI, "<this>");
        return (((int) aVarI.c) < 1048576 || (objG = kVar.g(iVar)) != kotlin.coroutines.intrinsics.a.a) ? Unit.a : objG;
    }
}
