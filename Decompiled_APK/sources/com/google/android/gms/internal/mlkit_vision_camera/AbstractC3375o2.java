package com.google.android.gms.internal.mlkit_vision_camera;

import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.features.practicetest.takingtest.data.C4408b;
import com.quizlet.features.practicetest.takingtest.data.C4409c;
import com.quizlet.features.practicetest.takingtest.data.C4411e;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.C4413g;
import com.quizlet.features.practicetest.takingtest.data.C4414h;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4410d;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.o2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3375o2 {
    /* JADX WARN: Multi-variable type inference failed */
    public static final void a(C4412f questionData, final InterfaceC4415i interfaceC4415i, Function1 onEvent, Function1 onAnswerSubmitted, Function0 onNextQuestion, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        int i5;
        C0814p c0814p;
        boolean z;
        int i6;
        boolean z2;
        boolean z3;
        C4411e c4411e;
        Intrinsics.checkNotNullParameter(questionData, "questionData");
        Intrinsics.checkNotNullParameter(onEvent, "onEvent");
        Intrinsics.checkNotNullParameter(onAnswerSubmitted, "onAnswerSubmitted");
        Intrinsics.checkNotNullParameter(onNextQuestion, "onNextQuestion");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(786118042);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.h(questionData) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.f(interfaceC4415i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.h(onEvent) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.h(onAnswerSubmitted) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.h(onNextQuestion) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p2.f(qVar) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i3 |= 524288;
        }
        if ((599187 & i3) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            i6 = i;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                i4 = i3 & (-3670017);
                i5 = AbstractC3205m5.g(c0814p2).a;
            } else {
                c0814p2.Q();
                i4 = i3 & (-3670017);
                i5 = i;
            }
            c0814p2.q();
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            int i7 = i4;
            androidx.compose.ui.q qVarG = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), androidx.compose.ui.graphics.F.a).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.h();
            float f = com.quizlet.ui.resources.designsystem.generated.h.g;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarG, DefinitionKt.NO_Float_VALUE, f, 1);
            mVar.h();
            androidx.compose.ui.q qVarU = AbstractC0460p.u(AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), AbstractC0460p.r(c0814p2), false, 14);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(i5 == 0 ? AbstractC0398m.c : AbstractC0398m.e, androidx.compose.ui.b.m, c0814p2, 0);
            int i8 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p2, i8, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.i();
            float f2 = com.quizlet.ui.resources.designsystem.generated.h.f;
            Q4.b(questionData.b, AbstractC0382e.w(nVar, f2, DefinitionKt.NO_Float_VALUE, 2), ((com.quizlet.themes.b) c0814p2.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).n, c0814p2, 0, 0, 65528);
            c0814p = c0814p2;
            List list = questionData.e;
            String str = (list == null || (c4411e = (C4411e) CollectionsKt.firstOrNull(list)) == null) ? null : c4411e.a;
            c0814p.X(1821967531);
            if (str == null) {
                z = false;
            } else {
                com.quizlet.data.model.R0 r0 = new com.quizlet.data.model.R0(str, null);
                z = false;
                O1.a(r0, null, c0814p, 0);
                Unit unit = Unit.a;
            }
            c0814p.p(z);
            InterfaceC4410d interfaceC4410d = questionData.d;
            boolean z4 = interfaceC4410d instanceof C4408b;
            androidx.compose.runtime.V v = C0804k.a;
            if (z4) {
                c0814p.X(1821974459);
                C4408b c4408b = (C4408b) interfaceC4410d;
                c0814p.X(1821977804);
                boolean z5 = (i7 & ContentType.LONG_FORM_ON_DEMAND) == 32;
                Object objI = c0814p.I();
                if (z5 || objI == v) {
                    z2 = false;
                    final Object[] objArr = 0 == true ? 1 : 0;
                    objI = new Function0() { // from class: com.quizlet.features.practicetest.takingtest.a
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (objArr) {
                                case 0:
                                    InterfaceC4415i interfaceC4415i2 = interfaceC4415i;
                                    if (interfaceC4415i2 instanceof C4413g) {
                                        return (C4413g) interfaceC4415i2;
                                    }
                                    return null;
                                default:
                                    InterfaceC4415i interfaceC4415i3 = interfaceC4415i;
                                    if (interfaceC4415i3 instanceof C4414h) {
                                        return (C4414h) interfaceC4415i3;
                                    }
                                    return null;
                            }
                        }
                    };
                    c0814p.i0(objI);
                } else {
                    z2 = false;
                }
                Function0 function0 = (Function0) objI;
                c0814p.p(z2);
                c0814p.X(1821981060);
                boolean z6 = ((i7 & 896) == 256) | ((i7 & 7168) == 2048);
                Object objI2 = c0814p.I();
                if (z6 || objI2 == v) {
                    z3 = false;
                    objI2 = new com.quizlet.features.practicetest.takingtest.b(onAnswerSubmitted, onEvent, 0 == true ? 1 : 0);
                    c0814p.i0(objI2);
                } else {
                    z3 = false;
                }
                c0814p.p(z3);
                mVar.g();
                AbstractC3386r2.a(c4408b, function0, (Function1) objI2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.h.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
                c0814p.p(false);
            } else {
                if (!(interfaceC4410d instanceof C4409c)) {
                    throw com.google.android.gms.measurement.internal.Z.j(1821972151, c0814p, false);
                }
                c0814p.X(1821996135);
                c0814p.X(1821997509);
                boolean z7 = (i7 & ContentType.LONG_FORM_ON_DEMAND) == 32;
                Object objI3 = c0814p.I();
                if (z7 || objI3 == v) {
                    final int i9 = 1;
                    objI3 = new Function0() { // from class: com.quizlet.features.practicetest.takingtest.a
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i9) {
                                case 0:
                                    InterfaceC4415i interfaceC4415i2 = interfaceC4415i;
                                    if (interfaceC4415i2 instanceof C4413g) {
                                        return (C4413g) interfaceC4415i2;
                                    }
                                    return null;
                                default:
                                    InterfaceC4415i interfaceC4415i3 = interfaceC4415i;
                                    if (interfaceC4415i3 instanceof C4414h) {
                                        return (C4414h) interfaceC4415i3;
                                    }
                                    return null;
                            }
                        }
                    };
                    c0814p.i0(objI3);
                }
                Function0 function02 = (Function0) objI3;
                c0814p.p(false);
                c0814p.X(1822000635);
                boolean z8 = ((i7 & 7168) == 2048) | ((i7 & 896) == 256);
                Object objI4 = c0814p.I();
                if (z8 || objI4 == v) {
                    objI4 = new com.quizlet.features.practicetest.takingtest.b(onAnswerSubmitted, onEvent, 1);
                    c0814p.i0(objI4);
                }
                c0814p.p(false);
                mVar.g();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.h.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                mVar.i();
                AbstractC3402v2.a(function02, (Function1) objI4, onNextQuestion, AbstractC0382e.w(qVarY, f2, DefinitionKt.NO_Float_VALUE, 2), c0814p, 6 | ((i7 >> 3) & 7168));
                c0814p.p(false);
            }
            c0814p.p(true);
            i6 = i5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.links.j(questionData, interfaceC4415i, onEvent, onAnswerSubmitted, onNextQuestion, qVar, i6, i2);
        }
    }

    public static View c(int i, View view) {
        if (!(view instanceof ViewGroup)) {
            return null;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View viewFindViewById = viewGroup.getChildAt(i2).findViewById(i);
            if (viewFindViewById != null) {
                return viewFindViewById;
            }
        }
        return null;
    }

    public abstract List b(String str, List list);
}
