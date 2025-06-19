package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.LayoutWeightElement;
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
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import com.quizlet.quizletandroid.R;
import com.quizlet.search.composables.AbstractC4786e;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.v0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3277v0 {
    public static C0867f a;

    /* JADX WARN: Removed duplicated region for block: B:104:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0247  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0261  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x026d  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x02a8  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x02c0 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:124:0x02c2  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02fc  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x02fe  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0316  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0209  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x020d  */
    /* JADX WARN: Type inference failed for: r0v15, types: [com.quizlet.search.composables.D] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final com.quizlet.assembly.compose.modals.x r27, final com.quizlet.search.data.SearchFiltersStates r28, final kotlin.jvm.functions.c r29, final kotlin.jvm.functions.Function1 r30, final kotlin.jvm.functions.Function1 r31, final kotlin.jvm.functions.Function1 r32, androidx.compose.runtime.InterfaceC0806l r33, int r34) {
        /*
            Method dump skipped, instructions count: 886
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0.a(com.quizlet.assembly.compose.modals.x, com.quizlet.search.data.SearchFiltersStates, kotlin.jvm.functions.c, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static final void b(InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, InterfaceC0773a0 interfaceC0773a03, androidx.compose.runtime.H0 h0) {
        Enum[] elements = {(EnumC4484g1) interfaceC0773a0.getValue(), (com.quizlet.generated.enums.Y0) interfaceC0773a02.getValue(), (EnumC4490i1) interfaceC0773a03.getValue()};
        Intrinsics.checkNotNullParameter(elements, "elements");
        h0.j(C4933y.z(elements).size());
    }

    public static final void c(int i, Enum r10, Object obj, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1537974665);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= (i2 & 64) == 0 ? c0814p.f(r10) : c0814p.h(r10) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= (i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(obj) : c0814p.h(obj) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strD = AbstractC3106b5.d(c0814p, i);
            boolean zB = Intrinsics.b(r10, obj);
            c0814p.X(-2027080473);
            boolean z = true;
            boolean z2 = (i3 & 7168) == 2048;
            if ((i3 & 896) != 256 && ((i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 || !c0814p.h(obj))) {
                z = false;
            }
            boolean z3 = z2 | z;
            Object objI = c0814p.I();
            if (z3 || objI == C0804k.a) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(6, function1, obj);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.X4.a(strD, zB, null, null, false, (Function0) objI, c0814p, 0, 28);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i, i2, 12, (Object) r10, obj, (InterfaceC4938g) function1);
        }
    }

    public static final void d(int i, Function0 onRestClick, com.quizlet.search.composables.D onApplyClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i2) {
        String strB;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onRestClick, "onRestClick");
        Intrinsics.checkNotNullParameter(onApplyClick, "onApplyClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1902434672);
        int i3 = i2 | (c0814p.d(i) ? 4 : 2) | (c0814p.h(onRestClick) ? 32 : 16) | (c0814p.h(onApplyClick) ? 256 : 128) | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            mVar.q();
            androidx.compose.ui.q qVarX = AbstractC0382e.x(qVarC, f, f, f, com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarX);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(AbstractC3106b5.d(c0814p, R.string.search_set_filters_reset), null, onRestClick, false, null, null, 0L, 0L, null, null, null, c0814p, (i3 << 3) & 896, 0, 4090);
            c0814p = c0814p;
            if (i == 0) {
                strB = com.google.android.gms.measurement.internal.Z.h(c0814p, 969556051, R.string.search_set_filters_apply_zero, c0814p, false);
            } else {
                c0814p.X(969645455);
                strB = AbstractC3106b5.b(R.plurals.search_set_filters_apply, i, new Object[]{Integer.valueOf(i)}, c0814p);
                c0814p.p(false);
            }
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            mVar.s();
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(strB, AbstractC0382e.y(layoutWeightElement, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), onApplyClick, false, null, null, null, null, null, false, c0814p, i3 & 896, 1016);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, i2, 26, onRestClick, onApplyClick, nVar2);
        }
    }

    public static final void e(EnumC4490i1 enumC4490i1, Function1 onSectionSelected, InterfaceC0806l interfaceC0806l, int i) {
        EnumC4490i1 enumC4490i12;
        Function1 function1;
        Intrinsics.checkNotNullParameter(onSectionSelected, "onSectionSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-726626777);
        int i2 = (c0814p.f(enumC4490i1) ? 4 : 2) | i | (c0814p.h(onSectionSelected) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            enumC4490i12 = enumC4490i1;
            function1 = onSectionSelected;
        } else {
            EnumC4490i1 enumC4490i13 = EnumC4490i1.ALL;
            int i3 = ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 384 | ((i2 << 6) & 7168);
            enumC4490i12 = enumC4490i1;
            function1 = onSectionSelected;
            c(R.string.search_set_filters_content_type_all, enumC4490i12, enumC4490i13, function1, c0814p, i3);
            c(R.string.search_set_filters_images, enumC4490i12, EnumC4490i1.IMAGES, function1, c0814p, i3);
            c(R.string.search_set_filters_diagrams, enumC4490i12, EnumC4490i1.DIAGRAMS, function1, c0814p, i3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(enumC4490i12, function1, i, 9);
        }
    }

    public static final void f(com.quizlet.generated.enums.Y0 y0, Function1 onSectionSelected, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.generated.enums.Y0 y02;
        Function1 function1;
        Intrinsics.checkNotNullParameter(onSectionSelected, "onSectionSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(969256148);
        int i2 = (c0814p.f(y0) ? 4 : 2) | i | (c0814p.h(onSectionSelected) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            y02 = y0;
            function1 = onSectionSelected;
        } else {
            com.quizlet.generated.enums.Y0 y03 = com.quizlet.generated.enums.Y0.ALL;
            int i3 = ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 384 | ((i2 << 6) & 7168);
            y02 = y0;
            function1 = onSectionSelected;
            c(R.string.search_set_filters_all, y02, y03, function1, c0814p, i3);
            c(R.string.search_set_filters_plus, y02, com.quizlet.generated.enums.Y0.PLUS, function1, c0814p, i3);
            c(R.string.search_set_filters_teacher, y02, com.quizlet.generated.enums.Y0.TEACHER, function1, c0814p, i3);
            c(R.string.search_set_filters_verified_creator, y02, com.quizlet.generated.enums.Y0.VERIFIED_CREATOR, function1, c0814p, i3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(y02, function1, i, 6);
        }
    }

    public static final void g(com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w onCloseClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onCloseClick, "onCloseClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-506400118);
        int i2 = (c0814p.h(onCloseClick) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            float f = 12;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar3, f, f, f, DefinitionKt.NO_Float_VALUE, 8);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.j();
            androidx.compose.material3.Z1.h(onCloseClick, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar3, com.quizlet.ui.resources.designsystem.generated.h.i), "searchFilterHeaderClose"), false, null, AbstractC4786e.a, c0814p, (i2 & 14) | 196608, 28);
            mVar.p();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar3, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            nVar2 = nVar3;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.toolbar_title_filters), qVarY2.g(new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true)), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(5), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).f, c0814p, 0, 0, 65016);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(onCloseClick, nVar2, i, 7);
        }
    }

    public static final void h(EnumC4484g1 enumC4484g1, Function1 onSectionSelected, InterfaceC0806l interfaceC0806l, int i) {
        EnumC4484g1 enumC4484g12;
        Function1 function1;
        Intrinsics.checkNotNullParameter(onSectionSelected, "onSectionSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(960499224);
        int i2 = (c0814p.f(enumC4484g1) ? 4 : 2) | i | (c0814p.h(onSectionSelected) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            enumC4484g12 = enumC4484g1;
            function1 = onSectionSelected;
        } else {
            EnumC4484g1 enumC4484g13 = EnumC4484g1.ALL;
            int i3 = ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 384 | ((i2 << 6) & 7168);
            enumC4484g12 = enumC4484g1;
            function1 = onSectionSelected;
            c(R.string.search_set_filters_num_terms_all, enumC4484g12, enumC4484g13, function1, c0814p, i3);
            c(R.string.search_set_filters_fewer_than_20, enumC4484g12, EnumC4484g1.LESS_THAN_TWENTY, function1, c0814p, i3);
            c(R.string.search_set_filters_20_to_49, enumC4484g12, EnumC4484g1.TWENTY_TO_FORTY_NINE, function1, c0814p, i3);
            c(R.string.search_set_filters_more_than_50, enumC4484g12, EnumC4484g1.GREATER_THAN_FIFTY, function1, c0814p, i3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(enumC4484g12, function1, i, 8);
        }
    }

    public static final void i(int i, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1731327158);
        if ((((c0814p.d(i) ? 4 : 2) | i2 | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar3, ((com.quizlet.themes.b) c0814p.j(b)).b.h(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.d(qVarF, com.quizlet.themes.m.A), 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, i);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).k;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.q();
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar3, f, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 10), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.ui.progress.c(i, nVar2, i2, 1);
        }
    }

    public static final void j(com.quizlet.assembly.compose.modals.x modalState, com.quizlet.search.viewmodels.A searchStudySetViewModel, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.compose.modals.x xVar;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(searchStudySetViewModel, "searchStudySetViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1033336184);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(searchStudySetViewModel) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            xVar = modalState;
        } else {
            xVar = modalState;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(xVar, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-1103399565, new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.x(modalState, searchStudySetViewModel, C0776c.m(searchStudySetViewModel.n, c0814p), 4), c0814p), c0814p, 1572872 | (i2 & 14), 62);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.A(xVar, searchStudySetViewModel, i, 0);
        }
    }

    public static final void k(final String text, final long j, final Function0 alpha, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        C0814p c0814p;
        final androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(alpha, "alpha");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1779486103);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.e(j) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(alpha) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            long jN = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.n();
            c0814p2.X(136424869);
            boolean z = (i3 & 896) == 256;
            Object objI = c0814p2.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.assembly.compose.input.d(9, alpha);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(androidx.compose.ui.graphics.F.p(nVar, (Function1) objI).g(androidx.compose.foundation.layout.K0.c), null, jN, 0L, j, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-1372062947, new com.quizlet.features.flashcards.views.composables.m(text, j), c0814p2), c0814p, (i3 << 9) & 57344, 1002);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.flashcards.views.composables.l
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function0 function0 = alpha;
                    q qVar3 = qVar2;
                    AbstractC3277v0.k(text, j, function0, qVar3, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void l(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 dragRightRatio, Function0 dragLeftRatio) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(dragRightRatio, "dragRightRatio");
        Intrinsics.checkNotNullParameter(dragLeftRatio, "dragLeftRatio");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(558086536);
        if ((i & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            c0814p.X(1989184672);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.q(new com.braze.support.u(10, dragLeftRatio));
                c0814p.i0(objI);
            }
            androidx.compose.runtime.W0 w0 = (androidx.compose.runtime.W0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(1989187778, c0814p, false);
            if (objG == v) {
                objG = C0776c.q(new com.braze.support.u(11, dragRightRatio));
                c0814p.i0(objG);
            }
            androidx.compose.runtime.W0 w02 = (androidx.compose.runtime.W0) objG;
            c0814p.p(false);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            qVar2 = qVar;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar2);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(1854161219);
            if (((Boolean) w02.getValue()).booleanValue()) {
                k(AbstractC3106b5.d(c0814p, R.string.flashcards_know), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).y(), dragRightRatio, null, c0814p, 384);
            }
            c0814p.p(false);
            c0814p.X(1854169272);
            if (((Boolean) w0.getValue()).booleanValue()) {
                k(AbstractC3106b5.d(c0814p, R.string.flashcards_still_learning), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).D(), dragLeftRatio, null, c0814p, 384);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.k(dragRightRatio, dragLeftRatio, qVar2, i, 0);
        }
    }
}
