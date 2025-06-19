package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.input.pointer.C0879b;
import androidx.compose.ui.n;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V4 {
    public static final void a(final String tagText, final Function1 onTextChange, androidx.compose.ui.n nVar, final boolean z, final EnumC4159q0 enumC4159q0, final Function0 function0, final Function0 function02, final Function0 function03, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p;
        final androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(tagText, "tagText");
        Intrinsics.checkNotNullParameter(onTextChange, "onTextChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1100524221);
        if (((i | (c0814p2.f(tagText) ? 4 : 2) | (c0814p2.h(onTextChange) ? 32 : 16) | 384 | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.f(enumC4159q0) ? 16384 : 8192) | (c0814p2.h(function0) ? 131072 : 65536) | (c0814p2.h(function02) ? 1048576 : 524288) | (c0814p2.h(function03) ? 8388608 : 4194304)) & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p2.j(AbstractC0955m0.n);
            c0814p = c0814p2;
            AbstractC0725t3.a(nVar3, androidx.compose.runtime.internal.e.e(1123083649, new com.quizlet.features.folders.edittags.composables.f(z, function0, q0, function02), c0814p2), androidx.compose.runtime.internal.e.e(-1886821118, new androidx.navigation.compose.o(18, q0, function03), c0814p2), null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(-638352180, new com.quizlet.features.folders.edittags.composables.g(tagText, onTextChange, enumC4159q0, q0, function02, 0), c0814p2), c0814p, 805306806, 440);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(tagText, onTextChange, nVar2, z, enumC4159q0, function0, function02, function03, i) { // from class: com.quizlet.features.folders.edittags.composables.d
                public final /* synthetic */ String a;
                public final /* synthetic */ Function1 b;
                public final /* synthetic */ n c;
                public final /* synthetic */ boolean d;
                public final /* synthetic */ EnumC4159q0 e;
                public final /* synthetic */ Function0 f;
                public final /* synthetic */ Function0 g;
                public final /* synthetic */ Function0 h;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function0 function04 = this.g;
                    Function0 function05 = this.h;
                    V4.a(this.a, this.b, this.c, this.d, this.e, this.f, function04, function05, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(String tagText, Function1 onTextChange, androidx.compose.ui.n nVar, boolean z, EnumC4159q0 enumC4159q0, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(tagText, "tagText");
        Intrinsics.checkNotNullParameter(onTextChange, "onTextChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-587233319);
        if (((i | (c0814p2.f(tagText) ? 4 : 2) | (c0814p2.h(onTextChange) ? 32 : 16) | 384 | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.f(enumC4159q0) ? 16384 : 8192) | (c0814p2.h(function0) ? 131072 : 65536) | (c0814p2.h(function02) ? 1048576 : 524288)) & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p2.j(AbstractC0955m0.n);
            c0814p = c0814p2;
            AbstractC3579a6.d(nVar3, androidx.compose.runtime.internal.e.e(1471937943, new com.quizlet.features.folders.edittags.composables.g(tagText, onTextChange, enumC4159q0, q0, function0, 1), c0814p2), com.quizlet.features.folders.edittags.composables.b.a, androidx.compose.runtime.internal.e.e(375019826, new com.quizlet.assembly.compose.modals.k(z, q0, function0, 1), c0814p2), androidx.compose.runtime.internal.e.e(-192952397, new com.quizlet.assembly.compose.input.m(13, q0, function02), c0814p2), 0, false, c0814p, 28086, 96);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(tagText, onTextChange, nVar2, z, enumC4159q0, function0, function02, i);
        }
    }

    public static final void c(com.quizlet.assembly.compose.modals.x modalState, androidx.compose.ui.n nVar, Function1 function1, kotlinx.collections.immutable.e eVar, com.quizlet.features.folders.edittags.viewmodel.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z;
        C0814p c0814p;
        int i3;
        com.quizlet.features.folders.edittags.viewmodel.c cVar2;
        androidx.compose.ui.n nVar2;
        com.quizlet.features.folders.edittags.viewmodel.c cVar3;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1183240901);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(modalState) : c0814p2.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i4 = i2 | 48;
        if ((i & 384) == 0) {
            i4 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i4 |= c0814p2.f(eVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i4 |= 8192;
        }
        if ((i4 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            cVar3 = cVar;
        } else {
            c0814p2.S();
            int i5 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i5 == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                z = false;
                c0814p = c0814p2;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.folders.edittags.viewmodel.c.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i3 = i4 & (-57345);
                cVar2 = (com.quizlet.features.folders.edittags.viewmodel.c) w0VarE;
                nVar2 = nVar3;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
                c0814p = c0814p2;
                z = false;
                i3 = i4 & (-57345);
                cVar2 = cVar;
            }
            c0814p.q();
            Boolean boolValueOf = Boolean.valueOf(modalState.b());
            c0814p.X(-1537380709);
            int i6 = i3 & 14;
            boolean zH = ((i6 == 4 || ((i3 & 8) != 0 && c0814p.h(modalState))) ? true : z) | c0814p.h(cVar2) | ((i3 & 7168) == 2048 ? true : z);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.folders.edittags.composables.j(modalState, cVar2, eVar, null);
                c0814p.i0(objI);
            }
            c0814p.p(z);
            C0776c.f(c0814p, boolValueOf, (Function2) objI);
            kotlinx.coroutines.flow.d0 d0Var = cVar2.h;
            c0814p.X(-1537366747);
            boolean z2 = ((i6 == 4 || ((i3 & 8) != 0 && c0814p.h(modalState))) ? true : z) | ((i3 & 896) == 256 ? true : z);
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.folders.edittags.composables.k(modalState, null, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(z);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH2 = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == v) {
                objI3 = new com.quizlet.features.folders.edittags.composables.i(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(cVar2.g, c0814p);
            c0814p.X(-1537361948);
            boolean zH3 = c0814p.h(cVar2);
            Object objI4 = c0814p.I();
            if (zH3 || objI4 == v) {
                objI4 = new com.quizlet.features.folders.edittags.composables.c(cVar2, 0);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            c0814p2 = c0814p;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(modalState, androidx.compose.runtime.internal.e.e(335909937, new com.quizlet.assembly.compose.menu.l(cVar2, modalState, interfaceC0773a0G, 10), c0814p), nVar2, androidx.compose.runtime.internal.e.e(1238830515, new androidx.navigation.compose.o(19, cVar2, interfaceC0773a0G), c0814p), com.quizlet.assembly.compose.modals.A.a, null, null, false, (Function0) objI4, c0814p2, i6 | 3128 | ((i3 << 3) & 896), 224);
            cVar3 = cVar2;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(modalState, nVar2, function1, eVar, cVar3, i);
        }
    }

    public static final void d(String text, Function1 onTextChange, EnumC4159q0 invalidTagType, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(onTextChange, "onTextChange");
        Intrinsics.checkNotNullParameter(invalidTagType, "invalidTagType");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2049813692);
        int i4 = i | (c0814p2.f(text) ? 4 : 2) | (c0814p2.h(onTextChange) ? 32 : 16) | (c0814p2.f(invalidTagType) ? 256 : 128);
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 = i4 | 3072;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 2048 : 1024);
        }
        int i6 = i3 | (c0814p2.h(function0) ? 16384 : 8192);
        if ((i6 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar3 = qVar2;
        } else {
            androidx.compose.ui.q qVar4 = i5 != 0 ? androidx.compose.ui.n.b : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            String strD = AbstractC3250r6.d(invalidTagType, c0814p2);
            String strD2 = AbstractC3106b5.d(c0814p2, R.string.tag_name);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(qVar4, 1.0f), "edit_tag_text_field");
            c0814p2.X(560932286);
            boolean zF = ((57344 & i6) == 16384) | c0814p2.f(strD);
            Object objI = c0814p2.I();
            if (zF || objI == v) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(strD, function0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.a(text, qVarG, onTextChange, strD2, null, 0, 0, null, null, 7, 0, (Function0) objI, strD, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p, (i6 & 14) | ((i6 << 3) & 896), 6, 0, 8375280);
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(text, onTextChange, invalidTagType, qVar3, function0, i, i2);
        }
    }

    public static final void e(boolean z, Function0 onBackClick, Function0 onSaveClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onBackClick, "onBackClick");
        Intrinsics.checkNotNullParameter(onSaveClick, "onSaveClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-505706995);
        int i2 = i | (c0814p.g(z) ? 4 : 2) | (c0814p.h(onBackClick) ? 32 : 16) | (c0814p.h(onSaveClick) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            String strD = AbstractC3106b5.d(c0814p, R.string.edit_tag);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(nVar3, strD, jG, 0L, com.quizlet.ui.resources.icons.d.u(c0814p), onBackClick, androidx.compose.runtime.internal.e.e(1515354991, new com.quizlet.features.flashcards.views.c(z, 1, onSaveClick), c0814p), null, c0814p, 1572870 | ((i2 << 12) & 458752), 136);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(z, onBackClick, onSaveClick, nVar2, i, 2);
        }
    }

    public static final void f(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-137754260);
        int i2 = i | 6 | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = androidx.compose.ui.n.b;
            String strD = AbstractC3106b5.d(c0814p, R.string.remove_tag);
            C4076a c4076a = C4076a.g;
            com.quizlet.assembly.compose.buttons.r rVar = com.quizlet.assembly.compose.buttons.r.a;
            com.quizlet.themes.m.g.q();
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(strD, androidx.compose.foundation.layout.K0.c(AbstractC0382e.u(qVar2, com.quizlet.ui.resources.designsystem.generated.j.i), 1.0f), function0, false, c4076a, rVar, null, null, null, false, c0814p, (i2 << 3) & 896, 968);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar2, function0, i, 3);
        }
    }

    public static final void g(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onSaveClick, boolean z) {
        int i2;
        Intrinsics.checkNotNullParameter(onSaveClick, "onSaveClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1554003575);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onSaveClick) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(AbstractC3106b5.d(c0814p, R.string.save_tag), qVar, onSaveClick, z, C4076a.h, com.quizlet.assembly.compose.buttons.r.a, null, null, null, false, c0814p, (i2 & 1008) | ((i2 << 9) & 7168), 960);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.edittags.composables.e(z, qVar, onSaveClick, i);
        }
    }

    public static final void h(com.quizlet.data.interactor.course.e eVar, androidx.compose.ui.input.pointer.n nVar) {
        boolean zA = androidx.compose.ui.input.pointer.l.a(nVar);
        androidx.compose.foundation.lazy.grid.m mVar = (androidx.compose.foundation.lazy.grid.m) eVar.c;
        androidx.compose.foundation.lazy.grid.m mVar2 = (androidx.compose.foundation.lazy.grid.m) eVar.b;
        if (zA) {
            androidx.compose.ui.input.pointer.util.a[] aVarArr = (androidx.compose.ui.input.pointer.util.a[]) mVar2.c;
            C4930v.o(aVarArr, null, 0, aVarArr.length);
            mVar2.b = 0;
            androidx.compose.ui.input.pointer.util.a[] aVarArr2 = (androidx.compose.ui.input.pointer.util.a[]) mVar.c;
            C4930v.o(aVarArr2, null, 0, aVarArr2.length);
            mVar.b = 0;
            eVar.a = 0L;
        }
        boolean zC = androidx.compose.ui.input.pointer.l.c(nVar);
        long j = nVar.b;
        if (!zC) {
            List list = nVar.k;
            if (list == null) {
                list = kotlin.collections.K.a;
            }
            int size = list.size();
            for (int i = 0; i < size; i++) {
                C0879b c0879b = (C0879b) list.get(i);
                long j2 = c0879b.a;
                long j3 = c0879b.c;
                mVar2.a(j2, androidx.compose.ui.geometry.b.d(j3));
                mVar.a(j2, androidx.compose.ui.geometry.b.e(j3));
            }
            long j4 = nVar.l;
            mVar2.a(j, androidx.compose.ui.geometry.b.d(j4));
            mVar.a(j, androidx.compose.ui.geometry.b.e(j4));
        }
        if (androidx.compose.ui.input.pointer.l.c(nVar) && j - eVar.a > 40) {
            androidx.compose.ui.input.pointer.util.a[] aVarArr3 = (androidx.compose.ui.input.pointer.util.a[]) mVar2.c;
            C4930v.o(aVarArr3, null, 0, aVarArr3.length);
            mVar2.b = 0;
            androidx.compose.ui.input.pointer.util.a[] aVarArr4 = (androidx.compose.ui.input.pointer.util.a[]) mVar.c;
            C4930v.o(aVarArr4, null, 0, aVarArr4.length);
            mVar.b = 0;
            eVar.a = 0L;
        }
        eVar.a = j;
    }

    public static final float i(float[] fArr, float[] fArr2) {
        int length = fArr.length;
        float f = DefinitionKt.NO_Float_VALUE;
        for (int i = 0; i < length; i++) {
            f += fArr[i] * fArr2[i];
        }
        return f;
    }

    public static final void j(float[] fArr, float[] fArr2, int i, float[] fArr3) {
        if (i == 0) {
            W4.e("At least one point must be provided");
            throw null;
        }
        int i2 = 2 >= i ? i - 1 : 2;
        int i3 = i2 + 1;
        float[][] fArr4 = new float[i3][];
        for (int i4 = 0; i4 < i3; i4++) {
            fArr4[i4] = new float[i];
        }
        for (int i5 = 0; i5 < i; i5++) {
            fArr4[0][i5] = 1.0f;
            for (int i6 = 1; i6 < i3; i6++) {
                fArr4[i6][i5] = fArr4[i6 - 1][i5] * fArr[i5];
            }
        }
        float[][] fArr5 = new float[i3][];
        for (int i7 = 0; i7 < i3; i7++) {
            fArr5[i7] = new float[i];
        }
        float[][] fArr6 = new float[i3][];
        for (int i8 = 0; i8 < i3; i8++) {
            fArr6[i8] = new float[i3];
        }
        int i9 = 0;
        while (i9 < i3) {
            float[] destination = fArr5[i9];
            float[] fArr7 = fArr4[i9];
            Intrinsics.checkNotNullParameter(fArr7, "<this>");
            Intrinsics.checkNotNullParameter(destination, "destination");
            System.arraycopy(fArr7, 0, destination, 0, i);
            for (int i10 = 0; i10 < i9; i10++) {
                float[] fArr8 = fArr5[i10];
                float fI = i(destination, fArr8);
                for (int i11 = 0; i11 < i; i11++) {
                    destination[i11] = destination[i11] - (fArr8[i11] * fI);
                }
            }
            float fSqrt = (float) Math.sqrt(i(destination, destination));
            if (fSqrt < 1.0E-6f) {
                fSqrt = 1.0E-6f;
            }
            float f = 1.0f / fSqrt;
            for (int i12 = 0; i12 < i; i12++) {
                destination[i12] = destination[i12] * f;
            }
            float[] fArr9 = fArr6[i9];
            int i13 = 0;
            while (i13 < i3) {
                fArr9[i13] = i13 < i9 ? DefinitionKt.NO_Float_VALUE : i(destination, fArr4[i13]);
                i13++;
            }
            i9++;
        }
        for (int i14 = i2; -1 < i14; i14--) {
            float fI2 = i(fArr5[i14], fArr2);
            float[] fArr10 = fArr6[i14];
            int i15 = i14 + 1;
            if (i15 <= i2) {
                int i16 = i2;
                while (true) {
                    fI2 -= fArr10[i16] * fArr3[i16];
                    if (i16 != i15) {
                        i16--;
                    }
                }
            }
            fArr3[i14] = fI2 / fArr10[i14];
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:26:0x0095 -> B:27:0x009b). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object k(com.quizlet.shared.models.api.notes.StudyNotesResponse r27, com.quizlet.shared.usecase.studynotes.q r28, kotlin.coroutines.jvm.internal.c r29) {
        /*
            Method dump skipped, instructions count: 302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.V4.k(com.quizlet.shared.models.api.notes.StudyNotesResponse, com.quizlet.shared.usecase.studynotes.q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
