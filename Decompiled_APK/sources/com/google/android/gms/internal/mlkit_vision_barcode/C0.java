package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.C0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C0 {
    public static C0867f a;

    public static final void a(androidx.compose.ui.n nVar, com.quizlet.assembly.compose.modals.x xVar, String str, com.quizlet.features.folders.addtofolder.data.u uVar, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.folders.addtofolder.data.u uVar2;
        Function1 function13;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(947185730);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(xVar) : c0814p.h(xVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            uVar2 = uVar;
            i2 |= c0814p.h(uVar2) ? 2048 : 1024;
        } else {
            uVar2 = uVar;
        }
        if ((i & 24576) == 0) {
            function13 = function1;
            i2 |= c0814p.h(function13) ? 16384 : 8192;
        } else {
            function13 = function1;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function12) ? 131072 : 65536;
        }
        int i3 = i2;
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            c0814p.X(1458055569);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.facebook.a(5, function12);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(1458059364, c0814p, false);
            if (objG == v) {
                objG = new com.quizlet.features.folders.addtofolder.composables.j(function12, xVar, 0);
                c0814p.i0(objG);
            }
            Function0 function02 = (Function0) objG;
            c0814p.p(false);
            com.quizlet.assembly.compose.modals.z zVar = com.quizlet.assembly.compose.modals.z.a;
            com.quizlet.assembly.compose.modals.A a2 = com.quizlet.assembly.compose.modals.A.a;
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-721750388, new com.quizlet.features.folders.addtofolder.composables.p(uVar2, str, function13, function12, function02, function0, 0), c0814p);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(-1594160950, new com.quizlet.features.folders.addtofolder.composables.p(uVar, str, function1, function12, function02, function0, 1), c0814p);
            c0814p.X(1458096559);
            boolean z = (458752 & i3) == 131072;
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.facebook.a(6, function12);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(xVar, dVarE, nVar, dVarE2, zVar, a2, null, false, (Function0) objI2, c0814p, ((i3 >> 3) & 14) | 3128 | ((i3 << 6) & 896), 192);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(nVar, xVar, str, uVar, function1, function12, i);
        }
    }

    public static final void b(androidx.compose.ui.n nVar, com.quizlet.features.folders.addtofolder.viewmodel.n nVar2, final com.quizlet.assembly.compose.modals.x xVar, final String str, kotlinx.collections.immutable.b bVar, final long j, final long j2, final String str2, final Function1 function1, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        C0814p c0814p;
        com.quizlet.features.folders.addtofolder.viewmodel.n nVar3;
        int i3;
        androidx.compose.ui.n nVar4;
        Boolean bool;
        C0814p c0814p2;
        com.quizlet.features.folders.addtofolder.viewmodel.n nVar5;
        final kotlinx.collections.immutable.b bVar2;
        final androidx.compose.ui.n nVar6;
        final com.quizlet.features.folders.addtofolder.viewmodel.n nVar7;
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-1765415851);
        int i4 = i | 6;
        if ((i & 48) == 0) {
            i4 = i | 22;
        }
        if ((i & 384) == 0) {
            i4 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p3.f(xVar) : c0814p3.h(xVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i4 |= c0814p3.f(str) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i4 |= c0814p3.h(bVar) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i4 |= c0814p3.e(j) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i4 |= c0814p3.e(j2) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i4 |= c0814p3.f(str2) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i4 |= c0814p3.h(function1) ? 67108864 : 33554432;
        }
        if ((38347923 & i4) == 38347922 && c0814p3.x()) {
            c0814p3.Q();
            nVar6 = nVar;
            nVar7 = nVar2;
            c0814p2 = c0814p3;
            bVar2 = bVar;
        } else {
            c0814p3.S();
            int i5 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i5 == 0 || c0814p3.w()) {
                androidx.compose.ui.n nVar8 = androidx.compose.ui.n.b;
                c0814p3.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                i2 = 67108864;
                Object objE = AbstractC3417z1.e(com.quizlet.features.folders.addtofolder.viewmodel.m.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p3);
                c0814p = c0814p3;
                c0814p.p(false);
                c0814p.p(false);
                nVar3 = (com.quizlet.features.folders.addtofolder.viewmodel.n) objE;
                i3 = i4 & (-113);
                nVar4 = nVar8;
            } else {
                c0814p3.Q();
                nVar3 = nVar2;
                i3 = i4 & (-113);
                c0814p = c0814p3;
                i2 = 67108864;
                nVar4 = nVar;
            }
            c0814p.q();
            com.quizlet.features.folders.addtofolder.viewmodel.m mVar = (com.quizlet.features.folders.addtofolder.viewmodel.m) nVar3;
            kotlinx.coroutines.flow.d0 d0Var = mVar.k;
            c0814p.X(1458017493);
            boolean z = true;
            int i6 = (i3 & 896) ^ 384;
            androidx.compose.ui.n nVar9 = nVar4;
            boolean z2 = ((i6 > 256 && c0814p.h(xVar)) || (i3 & 384) == 256) | ((234881024 & i3) == i2);
            Object objI = c0814p.I();
            if (z2 || objI == v) {
                objI = new com.quizlet.features.folders.addtofolder.composables.n(xVar, null, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j3 = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j3) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.features.folders.addtofolder.composables.m(interfaceC0773a0D, j3, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            com.quizlet.features.folders.addtofolder.data.u uVar = (com.quizlet.features.folders.addtofolder.data.u) C0776c.m(mVar.j, c0814p).getValue();
            c0814p.X(1458028921);
            boolean zH2 = c0814p.h(nVar3);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == v) {
                objI3 = new com.quizlet.explanations.textbook.ui.f(1, nVar3, com.quizlet.features.folders.addtofolder.viewmodel.n.class, "onAddMaterialToFolderEvent", "onAddMaterialToFolderEvent(Lcom/quizlet/features/folders/addtofolder/data/AddMaterialToFolderEvent;)V", 0, 18);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            Function1 function12 = (Function1) ((kotlin.reflect.f) objI3);
            int i7 = i3 >> 3;
            C0814p c0814p4 = c0814p;
            a(nVar9, xVar, str, uVar, function1, function12, c0814p4, (i3 & 14) | 64 | (i7 & ContentType.LONG_FORM_ON_DEMAND) | (i7 & 896) | ((i3 >> 12) & 57344));
            Boolean boolValueOf = Boolean.valueOf(xVar.b());
            c0814p4.X(1458033145);
            boolean zH3 = c0814p4.h(nVar3) | c0814p4.h(bVar) | ((458752 & i3) == 131072) | ((3670016 & i3) == 1048576) | ((29360128 & i3) == 8388608);
            if ((i6 <= 256 || !c0814p4.h(xVar)) && (i3 & 384) != 256) {
                z = false;
            }
            boolean z3 = zH3 | z;
            Object objI4 = c0814p4.I();
            if (z3 || objI4 == v) {
                bool = boolValueOf;
                c0814p2 = c0814p4;
                com.quizlet.features.folders.addtofolder.viewmodel.n nVar10 = nVar3;
                com.quizlet.features.folders.addtofolder.composables.o oVar = new com.quizlet.features.folders.addtofolder.composables.o(nVar10, bVar, j, j2, str2, xVar, null);
                nVar5 = nVar10;
                bVar2 = bVar;
                c0814p2.i0(oVar);
                objI4 = oVar;
            } else {
                c0814p2 = c0814p4;
                bool = boolValueOf;
                bVar2 = bVar;
                nVar5 = nVar3;
            }
            c0814p2.p(false);
            C0776c.g(bool, bVar2, (Function2) objI4, c0814p2);
            nVar6 = nVar9;
            nVar7 = nVar5;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.folders.addtofolder.composables.i
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    String str3 = str2;
                    Function1 function13 = function1;
                    C0.b(nVar6, nVar7, xVar, str, bVar2, j, j2, str3, function13, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(com.quizlet.features.folders.addtofolder.data.u uVar, androidx.compose.ui.q qVar, String str, Function1 function1, Function1 function12, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        androidx.compose.ui.q qVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-495283810);
        if (((i | (c0814p2.h(uVar) ? 4 : 2) | 48 | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024) | (c0814p2.h(function12) ? 16384 : 8192)) & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            qVar3 = qVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                qVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                qVar2 = qVar;
            }
            c0814p2.q();
            c0814p = c0814p2;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(qVar2, "AddToFolderModal_BottomSheetContent"), androidx.compose.runtime.internal.e.e(1557737562, new com.quizlet.assembly.compose.buttons.A(uVar, str, function12, function0), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(-1761588945, new com.quizlet.assembly.compose.menu.g(3, uVar, function1, function12, function02, false), c0814p2), c0814p, 805306416, 444);
            qVar3 = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.k(uVar, qVar3, str, function1, function12, function0, function02, i, 0);
        }
    }

    public static final void d(com.quizlet.features.folders.addtofolder.data.u uVar, androidx.compose.ui.q qVar, String str, Function1 function1, Function1 function12, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(303082670);
        int i2 = i | (c0814p.h(uVar) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.f(str) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function12) ? 16384 : 8192);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "AddToFolderModal_DialogContent");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            int i4 = i2 >> 3;
            D0.a(null, str, uVar.i, function12, function0, c0814p, i4 & 64624);
            B0.b(null, uVar, function1, function12, function02, c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (i4 & 896) | (i4 & 7168) | 24576, 1);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.k(uVar, qVar, str, function1, function12, function0, function02, i, 1);
        }
    }

    public static final void e(TermSearchUiModel termSearchUiModel, androidx.compose.ui.n nVar, int i, Function2 function2, com.quizlet.ui.compose.util.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(termSearchUiModel, "termSearchUiModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1268254455);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.f(termSearchUiModel) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        int i4 = i3 | 48;
        if ((i2 & 384) == 0) {
            i4 |= c0814p2.d(i) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p2.h(function2) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i4 |= (32768 & i2) == 0 ? c0814p2.f(aVar) : c0814p2.h(aVar) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i4 |= c0814p2.h(function0) ? 131072 : 65536;
        }
        if ((74899 & i4) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            c0814p2.X(455476997);
            boolean z = ((i4 & 14) == 4) | ((i4 & 7168) == 2048) | ((i4 & 896) == 256);
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.assembly.compose.cards.a(function2, termSearchUiModel, i, 11);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVarC, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-2090019279, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(termSearchUiModel, 5), c0814p2), c0814p2, 0, 990);
            c0814p = c0814p2;
            if (aVar != null) {
                P5.c(Long.valueOf(termSearchUiModel.a), function0, aVar, c0814p, ((i4 >> 6) & 896) | ((i4 >> 12) & ContentType.LONG_FORM_ON_DEMAND));
            }
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(termSearchUiModel, nVar2, i, function2, aVar, function0, i2, 11);
        }
    }
}
