package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.data.model.EssayInfo;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.i7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3171i7 {
    public static final void a(EssayInfo essayInfo, String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-389586918);
        if ((((c0814p.h(essayInfo) ? 4 : 2) | i | (c0814p.f(str) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            R5.c(null, 0L, 0L, androidx.compose.runtime.internal.e.e(577558381, new com.quizlet.assembly.compose.menu.l(qVar, essayInfo, str, 14), c0814p), c0814p, 3072);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 29, essayInfo, str, qVar);
        }
    }

    public static final void b(Function0 navigateBack, com.quizlet.features.notes.detail.viewmodels.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.features.notes.detail.viewmodels.d dVar2;
        Unit unit;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1015434596);
        int i3 = (c0814p.h(navigateBack) ? 4 : 2) | i | 16;
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            dVar2 = dVar;
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
                Object objE = AbstractC3417z1.e(com.quizlet.features.notes.detail.viewmodels.c.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-113);
                dVar2 = (com.quizlet.features.notes.detail.viewmodels.d) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-113);
                dVar2 = dVar;
            }
            c0814p.q();
            com.quizlet.features.notes.detail.viewmodels.c cVar = (com.quizlet.features.notes.detail.viewmodels.c) dVar2;
            kotlinx.coroutines.flow.d0 d0Var = cVar.g;
            c0814p.X(1532834341);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.notes.detail.composables.essay.d(navigateBack, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit2 = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.features.notes.detail.composables.essay.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit2, (Function2) objI2);
            c0814p.p(false);
            com.quizlet.features.notes.detail.states.d dVar3 = (com.quizlet.features.notes.detail.states.d) C0776c.m(cVar.f, c0814p).getValue();
            c0814p.X(1532843670);
            boolean zH = c0814p.h(dVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                unit = unit2;
                com.quizlet.explanations.textbook.ui.f fVar = new com.quizlet.explanations.textbook.ui.f(1, dVar2, com.quizlet.features.notes.detail.viewmodels.d.class, "onEventReceived", "onEventReceived(Lcom/quizlet/features/notes/common/events/MagicNotesEvent;)V", 0, 28);
                c0814p.i0(fVar);
                objI3 = fVar;
            } else {
                unit = unit2;
            }
            c0814p.p(false);
            c(dVar3, navigateBack, (Function1) ((kotlin.reflect.f) objI3), c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND);
            c0814p.X(1532845797);
            boolean zH2 = c0814p.h(dVar2);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == v) {
                objI4 = new com.quizlet.features.notes.detail.composables.essay.e(dVar2, null);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(navigateBack, dVar2, i, 19);
        }
    }

    public static final void c(com.quizlet.features.notes.detail.states.d dVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1483939704);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(dVar) : c0814p2.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "EssayScreen"), androidx.compose.runtime.internal.e.e(1962136892, new com.quizlet.explanations.questiondetail.ui.composables.m(10, function0), c0814p2), null, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(1068362439, new com.quizlet.assembly.compose.input.m(21, dVar, function1), c0814p2), c0814p, 805306422, 508);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 17, dVar, function0, function1);
        }
    }

    public static final void d(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1741062546);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            com.quizlet.themes.e.a(c0814p).a.getClass();
            function02 = function0;
            AbstractC3691o6.c(null, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function02, null, null, c0814p, (i2 << 15) & 458752, 203);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 1, function02);
        }
    }

    public static final void e(io.ktor.util.m mVar, io.ktor.util.m builder) {
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        Intrinsics.checkNotNullParameter(builder, "builder");
        for (Map.Entry entry : builder.a()) {
            mVar.e((String) entry.getKey(), (List) entry.getValue());
        }
    }

    public static final androidx.fragment.compose.e f(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Y(-496803845);
        androidx.fragment.compose.f fVar = androidx.fragment.compose.f.a;
        androidx.fragment.compose.g gVar = androidx.fragment.compose.g.a;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        androidx.fragment.compose.e eVar = (androidx.fragment.compose.e) L4.d(new Object[0], new com.quizlet.data.repository.explanations.myexplanations.a(fVar, false, gVar, 3), androidx.fragment.compose.h.a, c0814p, 3072, 4);
        c0814p.p(false);
        return eVar;
    }
}
