package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0393j0;
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
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3328d {
    public static final void a(com.quizlet.features.notes.upload.states.c cVar, String str, Function1 function1, Function0 function0, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-944720288);
        int i2 = i | (c0814p.f(cVar) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.f(qVar) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1875162038);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.w(str.length());
                c0814p.i0(objI);
            }
            androidx.compose.runtime.H0 h0 = (androidx.compose.runtime.H0) objI;
            c0814p.p(false);
            int i3 = h0.i();
            int i4 = cVar.c;
            c0814p.X(-605254275);
            int i5 = cVar.b;
            com.quizlet.features.notes.data.y yVar = ((i3 < i4 || i3 > i5) && i3 > 0) ? new com.quizlet.features.notes.data.y(AbstractC3106b5.b(R.plurals.magic_notes_characters_error, i3, new Object[]{Integer.valueOf(i4), Integer.valueOf(i5)}, c0814p), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a()) : null;
            c0814p.p(false);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(androidx.compose.ui.n.b, 1.0f);
            c0814p.X(1061435323);
            boolean z = (i2 & 896) == 256;
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.features.notes.upload.composables.pastetext.a(function1, h0, 0);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            AbstractC3324c.a(str, (Function1) objI2, qVarA, true, c0814p, ((i2 >> 3) & 14) | 3072);
            C7.a(h0.i(), cVar.b, yVar, null, function0, c0814p, (i2 << 3) & 57344);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(cVar, str, function1, function0, qVar, i, 4);
        }
    }

    public static final void b(Function0 navigateBack, Function0 navigateClose, Function2 navigateToSetPage, kotlin.jvm.functions.c navigateToMagicNotesDetail, com.quizlet.features.notes.upload.viewmodels.e eVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.notes.upload.viewmodels.e eVar2;
        int i2;
        com.quizlet.features.notes.upload.viewmodels.e eVar3;
        com.quizlet.features.notes.upload.viewmodels.e eVar4;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateClose, "navigateClose");
        Intrinsics.checkNotNullParameter(navigateToSetPage, "navigateToSetPage");
        Intrinsics.checkNotNullParameter(navigateToMagicNotesDetail, "navigateToMagicNotesDetail");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1721032997);
        int i3 = i | (c0814p.h(navigateBack) ? 4 : 2) | 8192;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            eVar4 = eVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.notes.upload.viewmodels.e.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                eVar2 = (com.quizlet.features.notes.upload.viewmodels.e) w0VarE;
                i2 = i3 & (-57345);
            } else {
                c0814p.Q();
                i2 = i3 & (-57345);
                eVar2 = eVar;
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(new kotlinx.coroutines.flow.Z(eVar2.E()), c0814p);
            kotlinx.coroutines.flow.Y y = new kotlinx.coroutines.flow.Y(eVar2.k);
            c0814p.X(-1844771446);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.notes.upload.composables.pastetext.d(navigateToMagicNotesDetail, navigateToSetPage, navigateBack, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(y) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.features.notes.upload.composables.pastetext.c(interfaceC0773a0D, j, null, y);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.features.notes.upload.states.h hVar = (com.quizlet.features.notes.upload.states.h) AbstractC4178x.k(unit, (Function2) objI2, c0814p, false, interfaceC0773a0M);
            c0814p.X(-1844752212);
            boolean zH = c0814p.h(eVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                eVar3 = eVar2;
                com.quizlet.features.notes.detail.composables.magicnotesdetail.G g = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, eVar3, com.quizlet.features.notes.upload.viewmodels.e.class, "onEventReceived", "onEventReceived(Lcom/quizlet/features/notes/common/events/MagicNotesEvent;)V", 0, 6);
                c0814p.i0(g);
                objI3 = g;
            } else {
                eVar3 = eVar2;
            }
            c0814p.p(false);
            d(hVar, navigateBack, navigateClose, (Function1) ((kotlin.reflect.f) objI3), c0814p, (i2 << 3) & 1008);
            eVar4 = eVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(navigateBack, navigateClose, (InterfaceC4938g) navigateToSetPage, (InterfaceC4938g) navigateToMagicNotesDetail, (Object) eVar4, i, 3);
        }
    }

    public static final void c(androidx.glance.p pVar, int i, int i2, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i3, int i4) {
        int i5;
        int i6;
        int i7;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1618370649);
        int i8 = i4 & 1;
        if (i8 != 0) {
            i5 = i3 | 6;
        } else {
            i5 = (c0814p.f(pVar) ? 4 : 2) | i3;
        }
        int i9 = i4 & 2;
        if (i9 != 0) {
            i6 = i5 | 48;
        } else {
            i6 = i5 | (c0814p.d(i) ? 32 : 16);
        }
        int i10 = i4 & 4;
        if (i10 != 0) {
            i7 = i6 | 384;
        } else {
            i7 = i6 | (c0814p.d(i2) ? 256 : 128);
        }
        if ((i7 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i8 != 0) {
                pVar = androidx.glance.n.a;
            }
            if (i9 != 0) {
                i = 0;
            }
            if (i10 != 0) {
                i2 = 0;
            }
            androidx.glance.layout.p pVar2 = androidx.glance.layout.p.a;
            c0814p.Y(578571862);
            c0814p.Y(-548224868);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(pVar2);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.layout.e.g);
            C0776c.E(c0814p, new androidx.glance.layout.b(i2), androidx.glance.layout.e.h);
            C0776c.E(c0814p, new androidx.glance.layout.a(i), androidx.glance.layout.e.i);
            dVar.invoke(androidx.glance.layout.r.a, c0814p, 54);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        androidx.glance.p pVar3 = pVar;
        int i11 = i;
        int i12 = i2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.glance.layout.q(pVar3, i11, i12, dVar, i3, i4);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v17 */
    /* JADX WARN: Type inference failed for: r10v3 */
    /* JADX WARN: Type inference failed for: r10v4, types: [boolean, int] */
    public static final void d(com.quizlet.features.notes.upload.states.h hVar, Function0 function0, Function0 function02, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        InterfaceC0773a0 interfaceC0773a0;
        int i3;
        InterfaceC0773a0 interfaceC0773a02;
        Object obj;
        InterfaceC0773a0 interfaceC0773a03;
        ?? r10;
        boolean z;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1082803054);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(hVar) : c0814p2.h(hVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function02) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Object obj2 = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(926617327);
            int i4 = i2 & 14;
            boolean z2 = i4 == 4 || ((i2 & 8) != 0 && c0814p2.h(hVar));
            Object objI = c0814p2.I();
            if (z2 || objI == obj2) {
                objI = new com.quizlet.featuregate.growthbook.a(hVar, 7);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p2, 0, 6);
            c0814p2.X(926620744);
            Object objI2 = c0814p2.I();
            if (objI2 == obj2) {
                objI2 = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI2);
            }
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) objI2;
            Object objG = com.google.android.gms.measurement.internal.Z.g(926623048, c0814p2, false);
            if (objG == obj2) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) objG;
            c0814p2.p(false);
            c0814p2.X(926625271);
            boolean zF = (i4 == 4 || ((i2 & 8) != 0 && c0814p2.h(hVar))) | c0814p2.f(interfaceC0773a04);
            int i5 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z3 = zF | (i5 == 32);
            Object objI3 = c0814p2.I();
            if (z3 || objI3 == obj2) {
                interfaceC0773a0 = interfaceC0773a05;
                i3 = i2;
                interfaceC0773a02 = interfaceC0773a06;
                obj = obj2;
                interfaceC0773a03 = interfaceC0773a04;
                r10 = 0;
                com.braze.communication.i iVar = new com.braze.communication.i(hVar, function0, interfaceC0773a02, interfaceC0773a03, interfaceC0773a0, 1);
                c0814p2.i0(iVar);
                objI3 = iVar;
            } else {
                interfaceC0773a0 = interfaceC0773a05;
                i3 = i2;
                interfaceC0773a02 = interfaceC0773a06;
                obj = obj2;
                interfaceC0773a03 = interfaceC0773a04;
                r10 = 0;
            }
            Function0 function03 = (Function0) objI3;
            c0814p2.p(r10);
            androidx.work.impl.t.a(r10, function03, c0814p2, r10, 1);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.a.a(AbstractC0460p.f(androidx.compose.ui.n.b, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), androidx.compose.ui.graphics.F.a), new C0393j0(3, 7)), "PasteTextScreen");
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(2136969258, new com.quizlet.explanations.questiondetail.ui.composables.m(12, function03), c0814p2);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(-1882132609, new com.quizlet.assembly.compose.input.h(hVar, function1, interfaceC0773a03, 8), c0814p2);
            Object obj3 = obj;
            AbstractC0725t3.a(qVarG, dVarE, null, null, null, 0, 0L, 0L, null, dVarE2, c0814p2, 805306416, 508);
            C0814p c0814p3 = c0814p2;
            c0814p3.X(926685115);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                c0814p3.X(926687572);
                boolean z4 = i5 == 32;
                Object objI4 = c0814p3.I();
                if (z4 || objI4 == obj3) {
                    objI4 = new com.braze.support.u(18, function0);
                    c0814p3.i0(objI4);
                }
                Function0 function04 = (Function0) objI4;
                z = false;
                Object objG2 = com.google.android.gms.measurement.internal.Z.g(926690120, c0814p3, false);
                if (objG2 == obj3) {
                    objG2 = new androidx.navigation.compose.z(interfaceC0773a0, 24);
                    c0814p3.i0(objG2);
                }
                c0814p3.p(false);
                AbstractC3320b.b(function04, (Function0) objG2, c0814p3, 48);
            } else {
                z = false;
            }
            c0814p3.p(z);
            c0814p = c0814p3;
            if (hVar instanceof com.quizlet.features.notes.upload.states.f) {
                c0814p = c0814p3;
                if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                    com.quizlet.data.model.m2 m2Var = ((com.quizlet.features.notes.upload.states.f) hVar).a;
                    c0814p3.X(926700107);
                    Object objI5 = c0814p3.I();
                    if (objI5 == obj3) {
                        objI5 = new androidx.navigation.compose.z(interfaceC0773a02, 25);
                        c0814p3.i0(objI5);
                    }
                    c0814p3.p(false);
                    M7.b(((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 384, c0814p3, m2Var, function02, (Function0) objI5);
                    c0814p = c0814p3;
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(hVar, function0, function02, function1, i, 17);
        }
    }

    public static final void e(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-769074942);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            function02 = function0;
            AbstractC3691o6.c(null, null, jG, 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function02, null, null, c0814p, (i2 << 15) & 458752, 203);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 2, function02);
        }
    }

    public static final kotlin.enums.b f(Enum[] entries) {
        Intrinsics.checkNotNullParameter(entries, "entries");
        return new kotlin.enums.b(entries);
    }
}
