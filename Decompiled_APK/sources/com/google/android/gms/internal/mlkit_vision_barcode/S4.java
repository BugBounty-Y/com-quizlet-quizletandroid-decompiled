package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.folders.data.C4316x0;
import com.quizlet.features.folders.data.InterfaceC4318y0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class S4 {
    public static final void a(com.quizlet.features.folders.data.Q0 q0, androidx.compose.ui.q qVar, boolean z, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1843563141);
        int i2 = i | (c0814p.h(q0) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            G4.b(q0, qVar, z, function1, c0814p, i2 & 8190);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(q0, qVar, z, function1, i, 1);
        }
    }

    public static final void b(com.quizlet.features.folders.data.U u, com.quizlet.features.folders.data.W0 w0, androidx.compose.ui.q qVar, androidx.compose.foundation.lazy.A a, float f, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        Function1 function14;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1341641533);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(u) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(w0) : c0814p.h(w0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(a) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.c(f) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            function13 = function1;
            i2 |= c0814p.h(function13) ? 131072 : 65536;
        } else {
            function13 = function1;
        }
        if ((1572864 & i) == 0) {
            function14 = function12;
            i2 |= c0814p.h(function14) ? 1048576 : 524288;
        } else {
            function14 = function12;
        }
        int i3 = i2;
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.r();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.e;
            mVar.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(M5.c(qVarC, a, f2, com.quizlet.ui.resources.designsystem.generated.j.i), "StudyMaterialsContentLazyColumn");
            mVar.s();
            androidx.compose.foundation.layout.A0 a0E = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h + f, 7);
            c0814p.X(-1104201661);
            boolean zH = c0814p.h(u) | ((458752 & i3) == 131072) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32 || ((i3 & 64) != 0 && c0814p.h(w0))) | ((3670016 & i3) == 1048576);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                androidx.navigation.internal.e eVar = new androidx.navigation.internal.e(u, w0, function14, function13, 4);
                c0814p.i0(eVar);
                objI = eVar;
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarG, a, a0E, null, null, null, false, (Function1) objI, c0814p, (i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND, 248);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.composables.Y(u, w0, qVar, a, f, function1, function12, i);
        }
    }

    public static androidx.compose.ui.geometry.d c(androidx.compose.ui.geometry.c cVar, long j, long j2, long j3, long j4, int i) {
        return new androidx.compose.ui.geometry.d(cVar.a, cVar.b, cVar.c, cVar.d, (i & 2) != 0 ? androidx.compose.ui.geometry.a.a : j, (i & 4) != 0 ? androidx.compose.ui.geometry.a.a : j2, (i & 8) != 0 ? androidx.compose.ui.geometry.a.a : j3, (i & 16) != 0 ? androidx.compose.ui.geometry.a.a : j4);
    }

    /* JADX WARN: Type inference failed for: r3v26, types: [java.lang.Iterable, java.lang.Object] */
    public static final void d(final com.quizlet.features.folders.data.U headerState, final com.quizlet.features.folders.data.W0 subFolderState, final com.quizlet.features.folders.data.P0 studyMaterialsState, androidx.compose.ui.q qVar, com.quizlet.features.folders.menu.u uVar, float f, InterfaceC4318y0 interfaceC4318y0, Function1 function1, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        com.quizlet.features.folders.menu.u uVar2;
        int i4;
        float f2;
        int i5;
        final InterfaceC4318y0 interfaceC4318y02;
        int i6;
        int i7;
        Function1 function12;
        com.quizlet.features.folders.menu.u uVar3;
        boolean z;
        Object c;
        int i8;
        androidx.compose.ui.q qVar3;
        InterfaceC4318y0 interfaceC4318y03;
        Function1 function13;
        final float f3;
        final Function1 function14;
        C0814p c0814p;
        final androidx.compose.ui.q qVar4;
        final com.quizlet.features.folders.menu.u uVar4;
        boolean z2;
        com.quizlet.features.folders.menu.u uVar5;
        boolean z3;
        String strH;
        boolean z4;
        androidx.compose.ui.graphics.painter.b bVarD;
        androidx.compose.ui.graphics.painter.b bVarL;
        Intrinsics.checkNotNullParameter(headerState, "headerState");
        Intrinsics.checkNotNullParameter(subFolderState, "subFolderState");
        Intrinsics.checkNotNullParameter(studyMaterialsState, "studyMaterialsState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-82828486);
        int i9 = (c0814p2.h(headerState) ? 4 : 2) | i | (c0814p2.f(subFolderState) ? 32 : 16);
        if ((i & 384) == 0) {
            i9 |= c0814p2.f(studyMaterialsState) ? 256 : 128;
        }
        int i10 = i2 & 8;
        if (i10 != 0) {
            i3 = i9 | 3072;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i9 | (c0814p2.f(qVar2) ? 2048 : 1024);
        }
        int i11 = i2 & 16;
        if (i11 != 0) {
            i4 = i3 | 24576;
            uVar2 = uVar;
        } else {
            uVar2 = uVar;
            i4 = i3 | (c0814p2.f(uVar2) ? 16384 : 8192);
        }
        int i12 = i2 & 32;
        if (i12 != 0) {
            i5 = i4 | 196608;
            f2 = f;
        } else {
            f2 = f;
            i5 = i4 | (c0814p2.c(f2) ? 131072 : 65536);
        }
        int i13 = i2 & 64;
        if (i13 != 0) {
            i6 = i5 | 1572864;
            interfaceC4318y02 = interfaceC4318y0;
        } else {
            interfaceC4318y02 = interfaceC4318y0;
            i6 = i5 | (c0814p2.f(interfaceC4318y02) ? 1048576 : 524288);
        }
        int i14 = i2 & 128;
        if (i14 != 0) {
            i7 = i6 | 12582912;
        } else {
            i7 = i6 | (c0814p2.h(function1) ? 8388608 : 4194304);
        }
        if ((i7 & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            function14 = function1;
            qVar4 = qVar2;
            c0814p = c0814p2;
            uVar4 = uVar2;
            f3 = f2;
        } else {
            androidx.compose.ui.q qVar5 = i10 != 0 ? androidx.compose.ui.n.b : qVar2;
            com.quizlet.features.folders.menu.s sVar = com.quizlet.features.folders.menu.s.a;
            com.quizlet.features.folders.menu.u uVar6 = i11 != 0 ? sVar : uVar2;
            if (i12 != 0) {
                f2 = 0;
            }
            InterfaceC4318y0 interfaceC4318y04 = i13 != 0 ? C4316x0.a : interfaceC4318y02;
            androidx.compose.runtime.V v = C0804k.a;
            if (i14 != 0) {
                c0814p2.X(1443302507);
                Object objI = c0814p2.I();
                if (objI == v) {
                    objI = new C4237k(8);
                    c0814p2.i0(objI);
                }
                function12 = (Function1) objI;
                c0814p2.p(false);
            } else {
                function12 = function1;
            }
            InterfaceC4318y0 interfaceC4318y05 = interfaceC4318y04;
            androidx.compose.foundation.lazy.A a = androidx.compose.foundation.lazy.D.a(0, c0814p2, 3);
            Function1 function15 = function12;
            com.quizlet.assembly.compose.menu.s sVarB = com.google.android.gms.internal.mlkit_vision_document_scanner.K5.b(c0814p2);
            c0814p2.X(1443307077);
            if (Intrinsics.b(uVar6, com.quizlet.features.folders.menu.r.a) || Intrinsics.b(uVar6, sVar)) {
                uVar3 = uVar6;
                z = false;
                sVarB.a();
            } else {
                if (!(uVar6 instanceof com.quizlet.features.folders.menu.t)) {
                    throw new NoWhenBranchMatchedException();
                }
                ?? r3 = ((com.quizlet.features.folders.menu.t) uVar6).a;
                c0814p2.X(-1704265152);
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(r3, 10));
                Iterator it2 = r3.iterator();
                while (it2.hasNext()) {
                    com.quizlet.features.folders.menu.q qVar6 = (com.quizlet.features.folders.menu.q) it2.next();
                    Iterator it3 = it2;
                    c0814p2.X(751173083);
                    boolean z5 = qVar6 instanceof com.quizlet.features.folders.menu.o;
                    if (z5) {
                        z2 = z5;
                        uVar5 = uVar6;
                        z3 = false;
                        strH = com.google.android.gms.measurement.internal.Z.h(c0814p2, 1383885995, R.string.add_tag, c0814p2, false);
                    } else {
                        z2 = z5;
                        uVar5 = uVar6;
                        z3 = false;
                        if (qVar6 instanceof com.quizlet.features.folders.menu.n) {
                            strH = com.google.android.gms.measurement.internal.Z.h(c0814p2, 1383888694, R.string.add_or_remove_tags, c0814p2, false);
                        } else {
                            if (!(qVar6 instanceof com.quizlet.features.folders.menu.p)) {
                                throw com.google.android.gms.measurement.internal.Z.j(1383884464, c0814p2, false);
                            }
                            strH = com.google.android.gms.measurement.internal.Z.h(c0814p2, 1383891778, R.string.remove_from_folder_action_a11y, c0814p2, false);
                        }
                    }
                    String str = strH;
                    c0814p2.p(z3);
                    c0814p2.X(1623385400);
                    if (z2) {
                        c0814p2.X(-704876875);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.L(c0814p2);
                        c0814p2.p(false);
                    } else if (qVar6 instanceof com.quizlet.features.folders.menu.n) {
                        c0814p2.X(-704874251);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        bVarL = com.quizlet.ui.resources.icons.d.L(c0814p2);
                        c0814p2.p(false);
                    } else {
                        if (!(qVar6 instanceof com.quizlet.features.folders.menu.p)) {
                            throw com.google.android.gms.measurement.internal.Z.j(-704879279, c0814p2, false);
                        }
                        c0814p2.X(-704871593);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        c0814p2.X(-1392792310);
                        z4 = false;
                        bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_minus, c0814p2, 0, false, false);
                        c0814p2.p(z4);
                        arrayList.add(new com.quizlet.assembly.compose.menu.o(qVar6, str, bVarD, null, false, null, false, 248));
                        it2 = it3;
                        uVar6 = uVar5;
                    }
                    bVarD = bVarL;
                    z4 = false;
                    c0814p2.p(z4);
                    arrayList.add(new com.quizlet.assembly.compose.menu.o(qVar6, str, bVarD, null, false, null, false, 248));
                    it2 = it3;
                    uVar6 = uVar5;
                }
                uVar3 = uVar6;
                z = false;
                c0814p2.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.J5.a(sVarB, arrayList);
            }
            c0814p2.p(z);
            androidx.compose.ui.q qVarA = androidx.compose.animation.H.a(qVar5, null, 3);
            c0814p2.X(1443325541);
            boolean zH = ((i7 & 896) == 256) | c0814p2.h(headerState) | ((3670016 & i7) == 1048576) | c0814p2.h(sVarB) | ((i7 & 57344) == 16384) | c0814p2.f(a) | ((29360128 & i7) == 8388608);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                i8 = i7;
                qVar3 = qVar5;
                c = new androidx.navigation.compose.C(studyMaterialsState, headerState, interfaceC4318y05, sVarB, uVar3, a, function15);
                interfaceC4318y03 = interfaceC4318y05;
                function13 = function15;
                c0814p2.i0(c);
            } else {
                i8 = i7;
                c = objI2;
                interfaceC4318y03 = interfaceC4318y05;
                function13 = function15;
                qVar3 = qVar5;
            }
            c0814p2.p(false);
            float f4 = f2;
            b(headerState, subFolderState, qVarA, a, f4, function13, (Function1) c, c0814p2, (i8 & 126) | ((i8 >> 3) & 57344) | ((i8 >> 6) & 458752));
            f3 = f4;
            function14 = function13;
            c0814p = c0814p2;
            qVar4 = qVar3;
            interfaceC4318y02 = interfaceC4318y03;
            uVar4 = uVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.folders.composables.X
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function1 function16 = function14;
                    S4.d(headerState, subFolderState, studyMaterialsState, qVar4, uVar4, f3, interfaceC4318y02, function16, (InterfaceC0806l) obj, iH, i2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(com.quizlet.features.folders.data.U0 u0, Function1 function1, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        String strD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(394834060);
        int i2 = i | (c0814p.h(u0) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            kotlinx.collections.immutable.b bVar = u0.a;
            c0814p.X(1204485231);
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
            Iterator<E> it2 = bVar.iterator();
            while (true) {
                boolean z = false;
                if (it2.hasNext()) {
                    com.quizlet.features.infra.models.folders.c cVar = (com.quizlet.features.infra.models.folders.c) it2.next();
                    com.quizlet.features.infra.models.folders.b bVar2 = cVar.b;
                    c0814p.X(-561020833);
                    if (bVar2 == com.quizlet.features.infra.models.folders.b.a) {
                        strD = AbstractC3106b5.d(c0814p, R.string.folder_all);
                    } else if (bVar2 == com.quizlet.features.infra.models.folders.b.b) {
                        strD = cVar.c;
                    } else {
                        if (bVar2 != com.quizlet.features.infra.models.folders.b.c) {
                            throw new NoWhenBranchMatchedException();
                        }
                        strD = "";
                    }
                    c0814p.p(false);
                    if (cVar.b == com.quizlet.features.infra.models.folders.b.c) {
                        z = true;
                    }
                    arrayList.add(new com.quizlet.features.infra.folder.a(strD, z, cVar.d));
                } else {
                    kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList);
                    c0814p.p(false);
                    c0814p.X(-392903392);
                    boolean zH = c0814p.h(bVar) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
                    Object objI = c0814p.I();
                    if (zH || objI == C0804k.a) {
                        objI = new com.quizlet.features.folders.composables.Z(function1, bVar);
                        c0814p.i0(objI);
                    }
                    c0814p.p(false);
                    E5.a(bVarI, u0.b, nVar3, (Function1) objI, u0.e, c0814p, 384, 0);
                    nVar2 = nVar3;
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 22, u0, function1, nVar2);
        }
    }

    public static final String f(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        return CollectionsKt.S(list, ",", null, null, com.quizlet.shared.quizletapi.utils.a.a, 30);
    }

    public static final boolean g(androidx.compose.ui.geometry.d dVar) {
        float fB = androidx.compose.ui.geometry.a.b(dVar.e);
        long j = dVar.e;
        if (fB != androidx.compose.ui.geometry.a.c(j)) {
            return false;
        }
        float fB2 = androidx.compose.ui.geometry.a.b(j);
        long j2 = dVar.f;
        if (fB2 != androidx.compose.ui.geometry.a.b(j2) || androidx.compose.ui.geometry.a.b(j) != androidx.compose.ui.geometry.a.c(j2)) {
            return false;
        }
        float fB3 = androidx.compose.ui.geometry.a.b(j);
        long j3 = dVar.g;
        if (fB3 != androidx.compose.ui.geometry.a.b(j3) || androidx.compose.ui.geometry.a.b(j) != androidx.compose.ui.geometry.a.c(j3)) {
            return false;
        }
        float fB4 = androidx.compose.ui.geometry.a.b(j);
        long j4 = dVar.h;
        return fB4 == androidx.compose.ui.geometry.a.b(j4) && androidx.compose.ui.geometry.a.b(j) == androidx.compose.ui.geometry.a.c(j4);
    }
}
