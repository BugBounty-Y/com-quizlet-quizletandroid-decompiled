package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import coil3.request.NullRequestDataException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3503o {
    public static final void a(com.quizlet.features.setpage.screenstates.v vVar, Function0 function0, Function1 function1, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.setpage.screenstates.v vVar2;
        boolean z;
        com.quizlet.assembly.compose.menu.s sVar;
        String str;
        boolean z2;
        String strH;
        androidx.compose.ui.graphics.painter.b bVarJ;
        boolean z3;
        Function0 function03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(656332154);
        int i3 = i | (c0814p.f(vVar) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
            vVar2 = vVar;
        } else {
            com.quizlet.assembly.compose.menu.s sVarB = K5.b(c0814p);
            c0814p.X(-922770773);
            if (Intrinsics.b(vVar, com.quizlet.features.setpage.screenstates.s.a)) {
                sVarB.a();
                i2 = i3;
                vVar2 = vVar;
            } else {
                String str2 = "items";
                if (vVar instanceof com.quizlet.features.setpage.screenstates.t) {
                    List list = ((com.quizlet.features.setpage.screenstates.t) vVar).a;
                    c0814p.X(-49569723);
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        com.quizlet.features.setpage.menu.data.k kVar = (com.quizlet.features.setpage.menu.data.k) it2.next();
                        c0814p.X(1552864765);
                        com.quizlet.features.setpage.menu.data.a aVar = com.quizlet.features.setpage.menu.data.a.a;
                        boolean zB = Intrinsics.b(kVar, aVar);
                        com.quizlet.features.setpage.menu.data.d dVar = com.quizlet.features.setpage.menu.data.d.a;
                        com.quizlet.features.setpage.menu.data.j jVar = com.quizlet.features.setpage.menu.data.j.a;
                        int i4 = i3;
                        com.quizlet.features.setpage.menu.data.i iVar = com.quizlet.features.setpage.menu.data.i.a;
                        com.quizlet.features.setpage.menu.data.h hVar = com.quizlet.features.setpage.menu.data.h.a;
                        com.quizlet.features.setpage.menu.data.g gVar = com.quizlet.features.setpage.menu.data.g.a;
                        Iterator it3 = it2;
                        com.quizlet.features.setpage.menu.data.f fVar = com.quizlet.features.setpage.menu.data.f.a;
                        com.quizlet.features.setpage.menu.data.e eVar = com.quizlet.features.setpage.menu.data.e.a;
                        com.quizlet.features.setpage.menu.data.b bVar = com.quizlet.features.setpage.menu.data.b.a;
                        com.quizlet.features.setpage.menu.data.c cVar = com.quizlet.features.setpage.menu.data.c.a;
                        if (zB) {
                            sVar = sVarB;
                            str = str2;
                            z2 = false;
                            strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593347918, R.string.class_add, c0814p, false);
                        } else {
                            sVar = sVarB;
                            str = str2;
                            z2 = false;
                            if (Intrinsics.b(kVar, bVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593345711, R.string.copy_set, c0814p, false);
                            } else if (Intrinsics.b(kVar, cVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593343469, R.string.delete_Set, c0814p, false);
                            } else if (Intrinsics.b(kVar, eVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593341095, R.string.save_for_offline, c0814p, false);
                            } else if (Intrinsics.b(kVar, fVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593338675, R.string.edit, c0814p, false);
                            } else if (Intrinsics.b(kVar, gVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593336292, R.string.remove_from_offline, c0814p, false);
                            } else if (Intrinsics.b(kVar, hVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593333705, R.string.report_content, c0814p, false);
                            } else if (Intrinsics.b(kVar, iVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593331136, R.string.set_page_progress_reset, c0814p, false);
                            } else if (Intrinsics.b(kVar, jVar)) {
                                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -593328466, R.string.share, c0814p, false);
                            } else {
                                if (!Intrinsics.b(kVar, dVar)) {
                                    throw com.google.android.gms.measurement.internal.Z.j(-593348846, c0814p, false);
                                }
                                c0814p.X(-1287538091);
                                c0814p.p(false);
                                strH = "Dev Tools";
                            }
                        }
                        c0814p.p(z2);
                        c0814p.X(-657945800);
                        if (Intrinsics.b(kVar, aVar)) {
                            c0814p.X(-20213603);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.D(c0814p);
                            c0814p.p(false);
                        } else if (Intrinsics.b(kVar, bVar)) {
                            c0814p.X(-20211653);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            c0814p.X(607329966);
                            bVarJ = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_copy, c0814p, 0, false, false);
                        } else if (Intrinsics.b(kVar, cVar)) {
                            c0814p.X(-20209698);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.z(c0814p);
                            c0814p.p(false);
                        } else if (Intrinsics.b(kVar, eVar)) {
                            c0814p.X(-20207585);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            c0814p.X(-548921842);
                            bVarJ = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_download, c0814p, 0, false, false);
                        } else if (Intrinsics.b(kVar, fVar)) {
                            c0814p.X(-20205573);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.v(c0814p);
                            c0814p.p(false);
                        } else if (Intrinsics.b(kVar, gVar)) {
                            c0814p.X(-20203362);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            c0814p.X(861133988);
                            bVarJ = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_offline, c0814p, 0, false, false);
                        } else if (Intrinsics.b(kVar, hVar)) {
                            c0814p.X(-20201317);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.x(c0814p);
                            c0814p.p(false);
                        } else if (Intrinsics.b(kVar, iVar)) {
                            c0814p.X(-20199234);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            c0814p.X(-1429313868);
                            bVarJ = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_refresh, c0814p, 0, false, false);
                        } else if (Intrinsics.b(kVar, jVar)) {
                            c0814p.X(-20197220);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.K(c0814p);
                            c0814p.p(false);
                        } else {
                            if (!Intrinsics.b(kVar, dVar)) {
                                throw com.google.android.gms.measurement.internal.Z.j(-20215227, c0814p, false);
                            }
                            c0814p.X(-20195265);
                            com.quizlet.themes.e.a(c0814p).a.getClass();
                            bVarJ = com.quizlet.ui.resources.icons.d.J(c0814p);
                            z3 = false;
                            c0814p.p(false);
                            c0814p.p(z3);
                            arrayList.add(new com.quizlet.assembly.compose.menu.o(kVar, strH, bVarJ, null, false, null, Intrinsics.b(kVar, cVar), 120));
                            i3 = i4;
                            it2 = it3;
                            sVarB = sVar;
                            str2 = str;
                        }
                        z3 = false;
                        c0814p.p(z3);
                        arrayList.add(new com.quizlet.assembly.compose.menu.o(kVar, strH, bVarJ, null, false, null, Intrinsics.b(kVar, cVar), 120));
                        i3 = i4;
                        it2 = it3;
                        sVarB = sVar;
                        str2 = str;
                    }
                    i2 = i3;
                    com.quizlet.assembly.compose.menu.s sVar2 = sVarB;
                    c0814p.p(false);
                    sVar2.getClass();
                    Intrinsics.checkNotNullParameter(arrayList, str2);
                    sVarB = sVar2;
                    sVarB.c(arrayList, true);
                    ((androidx.compose.runtime.L0) sVarB.c).setValue(com.quizlet.assembly.compose.menu.u.a);
                    z = false;
                    vVar2 = vVar;
                    c0814p.p(z);
                    com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                    mVar.s();
                    float f = -com.quizlet.ui.resources.designsystem.generated.j.h;
                    mVar.r();
                    function03 = function0;
                    M5.a(androidx.compose.runtime.internal.e.e(1985473441, new com.quizlet.explanations.questiondetail.ui.composables.m(18, function03), c0814p), null, sVarB, function1, new com.quizlet.assembly.compose.menu.r(new com.quizlet.assembly.compose.menu.t(N5.b(f, com.quizlet.ui.resources.designsystem.generated.j.e))), function02, c0814p, ((i2 << 3) & 7168) | 6 | (458752 & (i2 << 6)), 2);
                } else {
                    i2 = i3;
                    vVar2 = vVar;
                    if (!Intrinsics.b(vVar2, com.quizlet.features.setpage.screenstates.u.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    sVarB.getClass();
                    kotlin.collections.K items = kotlin.collections.K.a;
                    Intrinsics.checkNotNullParameter(items, "items");
                    sVarB.c(items, true);
                    ((androidx.compose.runtime.L0) sVarB.c).setValue(com.quizlet.assembly.compose.menu.u.d);
                }
            }
            z = false;
            c0814p.p(z);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            mVar2.s();
            float f2 = -com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar2.r();
            function03 = function0;
            M5.a(androidx.compose.runtime.internal.e.e(1985473441, new com.quizlet.explanations.questiondetail.ui.composables.m(18, function03), c0814p), null, sVarB, function1, new com.quizlet.assembly.compose.menu.r(new com.quizlet.assembly.compose.menu.t(N5.b(f2, com.quizlet.ui.resources.designsystem.generated.j.e))), function02, c0814p, ((i2 << 3) & 7168) | 6 | (458752 & (i2 << 6)), 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) vVar2, function03, function1, function02, i, 26);
        }
    }

    public static final coil3.request.c b(coil3.request.g gVar, Throwable th) {
        coil3.j jVar;
        if (th instanceof NullRequestDataException) {
            jVar = (coil3.j) gVar.n.invoke(gVar);
            coil3.request.e eVar = gVar.t;
            if (jVar == null) {
                jVar = (coil3.j) eVar.j.invoke(gVar);
            }
            if (jVar == null && (jVar = (coil3.j) gVar.m.invoke(gVar)) == null) {
                jVar = (coil3.j) eVar.i.invoke(gVar);
            }
        } else {
            jVar = (coil3.j) gVar.m.invoke(gVar);
            if (jVar == null) {
                jVar = (coil3.j) gVar.t.i.invoke(gVar);
            }
        }
        return new coil3.request.c(jVar, gVar, th);
    }

    public static final void c(Function0 navigateUp, com.quizlet.features.setpage.viewmodel.P setPageViewModel, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(navigateUp, "navigateUp");
        Intrinsics.checkNotNullParameter(setPageViewModel, "setPageViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1148287382);
        if ((((c0814p.h(navigateUp) ? 4 : 2) | i | (c0814p.f(setPageViewModel) ? 32 : 16) | 384) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            AbstractC3178j5.c(null, false, null, androidx.compose.runtime.internal.e.e(-1866820248, new com.quizlet.features.practicetest.results.i(setPageViewModel, navigateUp), c0814p), c0814p, 3072, 7);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(navigateUp, setPageViewModel, nVar2, i, 11);
        }
    }
}
