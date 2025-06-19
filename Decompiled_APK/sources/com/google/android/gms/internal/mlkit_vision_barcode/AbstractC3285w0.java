package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.vector.C0866e;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.graphics.vector.C0872k;
import androidx.compose.ui.graphics.vector.C0873l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3285w0;
import com.quizlet.generated.enums.EnumC4497l;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.w0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3285w0 {
    public static C0867f a;

    public static final void a(final androidx.compose.foundation.shape.d dVar, final long j, final long j2, final String str, final long j3, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1445549699);
        int i2 = (c0814p.f(dVar) ? 4 : 2) | i;
        if ((i & 48) == 0) {
            i2 |= c0814p.e(j) ? 32 : 16;
        }
        int i3 = i2 | (c0814p.e(j2) ? 256 : 128);
        if ((i & 3072) == 0) {
            i3 |= c0814p.f(str) ? 2048 : 1024;
        }
        int i4 = i3 | (c0814p.e(j3) ? 16384 : 8192);
        if ((196608 & i) == 0) {
            i4 |= c0814p.f(qVar) ? 131072 : 65536;
        }
        if ((74899 & i4) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.ui.draw.g.c(qVar, dVar), j2, androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.K0.b(AbstractC0460p.g(qVarF, com.quizlet.themes.m.h, j, dVar), com.quizlet.themes.m.E0, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarB);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).g;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.u();
            androidx.compose.material3.Q4.b(str, c0418x.a(AbstractC0382e.v(nVar, f, com.quizlet.ui.resources.designsystem.generated.j.g), androidx.compose.ui.b.e), j3, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, ((i4 >> 9) & 14) | ((i4 >> 6) & 896), 0, 65528);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.flashcards.views.composables.o
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    long j4 = j3;
                    q qVar2 = qVar;
                    AbstractC3285w0.a(dVar, j, j2, str, j4, qVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(com.quizlet.ui.models.search.c searchShortcutModel, Function1 onClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        String string;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(searchShortcutModel, "searchShortcutModel");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-452635372);
        int i4 = i | (c0814p2.h(searchShortcutModel) ? 4 : 2) | (c0814p2.h(onClick) ? 32 : 16) | 384;
        if ((i4 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.data.model.search.c cVar = searchShortcutModel.a;
            Intrinsics.checkNotNullParameter(cVar, "<this>");
            int i5 = com.quizlet.ui.models.mappers.c.a[cVar.c.ordinal()];
            if (i5 == 1) {
                i2 = R.string.search_literature_guide_button_text;
            } else if (i5 == 2) {
                i2 = R.string.search_exam_button_text;
            } else {
                if (i5 != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                i2 = R.string.search_subject_button_text;
            }
            Object[] args = {cVar.b};
            Intrinsics.checkNotNullParameter(args, "args");
            List listP = C4933y.P(args);
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(context, "context");
            if (listP == null || listP.isEmpty()) {
                string = context.getString(i2);
                Intrinsics.d(string);
            } else {
                Object[] array = AbstractC3058t1.b(context, listP).toArray(new Object[0]);
                string = context.getString(i2, Arrays.copyOf(array, array.length));
                Intrinsics.d(string);
            }
            String string2 = string.toString();
            EnumC4497l enumC4497l = searchShortcutModel.a.a;
            boolean zQ = AbstractC0460p.q(c0814p2);
            Intrinsics.checkNotNullParameter(enumC4497l, "<this>");
            switch (com.quizlet.ui.models.mappers.a.a[enumC4497l.ordinal()]) {
                case 1:
                    i3 = R.drawable.ic_brand_math;
                    break;
                case 2:
                    i3 = R.drawable.ic_brand_languages;
                    break;
                case 3:
                    i3 = R.drawable.ic_brand_literature;
                    break;
                case 4:
                    i3 = R.drawable.ic_brand_social_science;
                    break;
                case 5:
                    i3 = R.drawable.ic_brand_standardized_english;
                    break;
                case 6:
                    i3 = R.drawable.ic_brand_standardized_test;
                    break;
                case 7:
                    if (!zQ) {
                        i3 = R.drawable.ic_brand_science_light;
                        break;
                    } else {
                        i3 = R.drawable.ic_brand_science_dark;
                        break;
                    }
                default:
                    throw new NoWhenBranchMatchedException();
            }
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p2.X(386260215);
            boolean zH = c0814p2.h(searchShortcutModel) | ((i4 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p2.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(7, onClick, searchShortcutModel);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVarY, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(690782874, new com.quizlet.features.flashcards.settings.ui.h(i3, string2, 2), c0814p2), c0814p, 0, 990);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(searchShortcutModel, onClick, nVar2, i, 14);
        }
    }

    public static final void c(int i, int i2, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, int i3, InterfaceC0806l interfaceC0806l, int i4) {
        int i5;
        androidx.compose.ui.n nVar;
        androidx.compose.ui.n nVar2;
        Function0 function03;
        int i6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1393972315);
        if (((i4 | (c0814p.d(i) ? 4 : 2) | (c0814p.d(i2) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | 65536) & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
            function03 = function02;
            i6 = i3;
        } else {
            c0814p.S();
            int i7 = i4 & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i7 == 0 || c0814p.w()) {
                i5 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i5 = i3;
            }
            c0814p.q();
            c0814p.X(718654471);
            boolean zD = c0814p.d(i5);
            Object objI = c0814p.I();
            if (zD || objI == v) {
                Set set = androidx.compose.material3.windowsizeclass.c.b;
                objI = Boolean.valueOf(!(i5 == 0));
                c0814p.i0(objI);
            }
            boolean zBooleanValue = ((Boolean) objI).booleanValue();
            c0814p.p(false);
            c0814p.X(718659853);
            boolean zG = c0814p.g(zBooleanValue);
            Object objI2 = c0814p.I();
            if (zG || objI2 == v) {
                if (zBooleanValue) {
                    com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                    mVar.b();
                    float f = com.quizlet.ui.resources.designsystem.generated.f.j;
                    androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(f);
                    mVar.b();
                    objI2 = new Pair(dVarA, androidx.compose.foundation.shape.e.a(f));
                } else {
                    com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
                    mVar2.b();
                    float f2 = com.quizlet.ui.resources.designsystem.generated.f.j;
                    mVar2.b();
                    androidx.compose.foundation.shape.d dVarB = androidx.compose.foundation.shape.e.b(DefinitionKt.NO_Float_VALUE, f2, 9);
                    mVar2.b();
                    mVar2.b();
                    objI2 = new Pair(dVarB, androidx.compose.foundation.shape.e.b(f2, DefinitionKt.NO_Float_VALUE, 6));
                }
                c0814p.i0(objI2);
            }
            Pair pair = (Pair) objI2;
            c0814p.p(false);
            androidx.compose.foundation.shape.d dVar = (androidx.compose.foundation.shape.d) pair.a;
            androidx.compose.foundation.shape.d dVar2 = (androidx.compose.foundation.shape.d) pair.b;
            C0386g c0386g = AbstractC0398m.g;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0386g, hVar, c0814p, 54);
            int i8 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i9 = c0814p.P;
            int i10 = i5;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            a(dVar, AbstractC3169i5.f(c0814p).k0, AbstractC3169i5.f(c0814p).j0, String.valueOf(i2), AbstractC3169i5.f(c0814p).E(), androidx.compose.ui.platform.N.G(nVar3, "still_learning_counter"), c0814p, 196608);
            long j = C0861v.f;
            long jD = AbstractC3169i5.f(c0814p).D();
            long jO = AbstractC3169i5.f(c0814p).o();
            c0814p.X(552699133);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new com.quizlet.assembly.compose.input.d(10, function0);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            a(dVar, j, jD, "+1", jO, androidx.compose.ui.platform.N.G(androidx.compose.ui.graphics.F.p(nVar3, (Function1) objI3), "still_learning_drag_counter"), c0814p, 3120);
            c0814p.p(true);
            c0814p.X(-412700603);
            if (zBooleanValue) {
                String strD = AbstractC3106b5.d(c0814p, R.string.flashcards_still_learning);
                androidx.compose.ui.text.L l = AbstractC3169i5.g(c0814p).j;
                long j2 = AbstractC3169i5.f(c0814p).l0;
                com.quizlet.themes.m.g.p();
                nVar = nVar3;
                androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar3, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), j2, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
                c0814p = c0814p;
            } else {
                nVar = nVar3;
            }
            c0814p.p(false);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true));
            c0814p.X(-412686270);
            if (zBooleanValue) {
                String strD2 = AbstractC3106b5.d(c0814p, R.string.flashcards_know);
                androidx.compose.ui.text.L l2 = AbstractC3169i5.g(c0814p).j;
                long j3 = AbstractC3169i5.f(c0814p).t0;
                com.quizlet.themes.m.g.p();
                androidx.compose.ui.n nVar4 = nVar;
                C0814p c0814p2 = c0814p;
                nVar2 = nVar4;
                androidx.compose.material3.Q4.b(strD2, AbstractC0382e.y(nVar4, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, 11), j3, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p2, 0, 0, 65528);
                c0814p = c0814p2;
            } else {
                nVar2 = nVar;
            }
            c0814p.p(false);
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
            int i11 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, nVar2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i11))) {
                android.support.v4.media.session.a.z(i11, c0814p, i11, c0912h3);
            }
            C0776c.E(c0814p, qVarC4, c0912h4);
            a(dVar2, AbstractC3169i5.f(c0814p).h0, AbstractC3169i5.f(c0814p).g0, String.valueOf(i), AbstractC3169i5.f(c0814p).z(), androidx.compose.ui.platform.N.G(nVar2, "know_counter"), c0814p, 196608);
            long jY = AbstractC3169i5.f(c0814p).y();
            long jO2 = AbstractC3169i5.f(c0814p).o();
            c0814p.X(552757214);
            Object objI4 = c0814p.I();
            if (objI4 == v) {
                function03 = function02;
                objI4 = new com.quizlet.assembly.compose.input.d(11, function03);
                c0814p.i0(objI4);
            } else {
                function03 = function02;
            }
            c0814p.p(false);
            a(dVar2, j, jY, "+1", jO2, androidx.compose.ui.platform.N.G(androidx.compose.ui.graphics.F.p(nVar2, (Function1) objI4), "know_drag_counter"), c0814p, 3120);
            c0814p.p(true);
            c0814p.p(true);
            i6 = i10;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.n(i, i2, qVar, function0, function03, i6, i4);
        }
    }

    public static final C0867f d() {
        C0867f c0867f = a;
        if (c0867f != null) {
            return c0867f;
        }
        C0866e c0866e = new C0866e("Filled.Circle", 24.0f, 24.0f, 24.0f, 24.0f, 0L, 0, false, 96);
        kotlin.collections.K k = androidx.compose.ui.graphics.vector.I.a;
        androidx.compose.ui.graphics.X x = new androidx.compose.ui.graphics.X(C0861v.b);
        ArrayList arrayList = new ArrayList(32);
        arrayList.add(new androidx.compose.ui.graphics.vector.o(12.0f, 2.0f));
        arrayList.add(new C0873l(6.47f, 2.0f, 2.0f, 6.47f, 2.0f, 12.0f));
        arrayList.add(new androidx.compose.ui.graphics.vector.y(4.47f, 10.0f, 10.0f, 10.0f));
        arrayList.add(new androidx.compose.ui.graphics.vector.y(10.0f, -4.47f, 10.0f, -10.0f));
        arrayList.add(new androidx.compose.ui.graphics.vector.q(17.53f, 2.0f, 12.0f, 2.0f));
        arrayList.add(C0872k.c);
        C0866e.a(c0866e, arrayList, x);
        C0867f c0867fB = c0866e.b();
        a = c0867fB;
        return c0867fB;
    }
}
