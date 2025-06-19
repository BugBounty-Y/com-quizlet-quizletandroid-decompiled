package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.material3.AbstractC0618f4;
import androidx.compose.material3.C0602d0;
import androidx.compose.material3.C0624g4;
import androidx.compose.material3.EnumC0630h4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.comscore.streaming.ContentType;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.folders.composables.AbstractC4248d;
import com.quizlet.features.folders.data.C4284h;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public abstract class P4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(Function1 function1, String str, com.quizlet.generated.enums.y1 y1Var, boolean z, androidx.compose.ui.n nVar, boolean z2, Function1 function12, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function13;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.n nVar3;
        int i2 = 0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-61719259);
        if (((i | (c0814p.h(function1) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.f(y1Var) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | 24576 | (c0814p.g(z2) ? 131072 : 65536)) & 4793491) == 4793490 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            function13 = function12;
        } else {
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(1368115108);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.t(new androidx.compose.runtime.internal.d(true, -1202337831, new com.quizlet.assembly.compose.input.f(dVar, 5)));
                c0814p.i0(objI);
            }
            Function2 function2 = (Function2) objI;
            c0814p.p(false);
            if (z) {
                c0814p.X(-537986283);
                c0814p.X(1368120532);
                androidx.compose.runtime.X0 x0 = AbstractC0955m0.f;
                androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(x0);
                c0814p.X(-1357302088);
                boolean zF = c0814p.f(bVar);
                Object objI2 = c0814p.I();
                if (zF || objI2 == v) {
                    objI2 = new com.quizlet.features.folders.composables.J(bVar, i2);
                    c0814p.i0(objI2);
                }
                Function1 function14 = (Function1) objI2;
                c0814p.p(false);
                c0814p.p(false);
                c0814p.X(-362555404);
                EnumC0630h4 enumC0630h4 = EnumC0630h4.c;
                c0814p.X(214094653);
                Object objI3 = c0814p.I();
                if (objI3 == v) {
                    objI3 = new C4237k(7);
                    c0814p.i0(objI3);
                }
                Function1 function15 = (Function1) objI3;
                c0814p.p(false);
                androidx.compose.ui.unit.b bVar2 = (androidx.compose.ui.unit.b) c0814p.j(x0);
                Object[] objArr = {null};
                C0602d0 c0602d0 = C0602d0.C;
                androidx.activity.compose.g gVar = new androidx.activity.compose.g(bVar2, function15, function14, 18);
                com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
                com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(c0602d0, false, gVar, 3);
                c0814p.X(214107867);
                boolean zF2 = c0814p.f(enumC0630h4) | c0814p.f(bVar2) | c0814p.f(function15) | c0814p.f(function14);
                Object objI4 = c0814p.I();
                if (zF2 || objI4 == v) {
                    objI4 = new androidx.work.impl.utils.o(enumC0630h4, bVar2, function15, function14, 5);
                    c0814p.i0(objI4);
                }
                c0814p.p(false);
                C0624g4 c0624g4 = (C0624g4) L4.d(objArr, aVar2, (Function0) objI4, c0814p, 0, 4);
                c0814p.p(false);
                androidx.compose.runtime.internal.d dVar2 = AbstractC4248d.a;
                androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1981557757, new com.quizlet.baseui.base.d(function2, 1), c0814p);
                nVar2 = nVar4;
                AbstractC0618f4.a(c0624g4, nVar2, false, false, false, dVarE, c0814p, 1576368);
                c0814p = c0814p;
                int iOrdinal = ((EnumC0630h4) ((androidx.compose.runtime.L0) ((InterfaceC0773a0) c0624g4.b.g)).getValue()).ordinal();
                if (iOrdinal == 0) {
                    function13 = function12;
                    c0814p.p(false);
                } else {
                    if (iOrdinal == 1) {
                        if (!z2) {
                            function1.invoke(new C4284h(str, y1Var));
                            function13 = function12;
                            function13.invoke(Boolean.TRUE);
                        }
                        c0814p.p(false);
                    } else if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    function13 = function12;
                    c0814p.p(false);
                }
            } else {
                function13 = function12;
                nVar2 = nVar4;
                c0814p.X(-536453488);
                function2.invoke(c0814p, 6);
                c0814p.p(false);
            }
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.c(function1, str, y1Var, z, nVar3, z2, function13, dVar, i);
        }
    }

    public static final void b(com.quizlet.ui.models.content.listitem.o oVar, int i, Function1 function1, boolean z, boolean z2, androidx.compose.foundation.lazy.A a2, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        Function1 function12;
        boolean z3;
        boolean z4;
        androidx.compose.foundation.lazy.A a3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1765964581);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(oVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 = i;
            i3 |= c0814p.d(i4) ? 32 : 16;
        } else {
            i4 = i;
        }
        if ((i2 & 384) == 0) {
            function12 = function1;
            i3 |= c0814p.h(function12) ? 256 : 128;
        } else {
            function12 = function1;
        }
        if ((i2 & 3072) == 0) {
            z3 = z;
            i3 |= c0814p.g(z3) ? 2048 : 1024;
        } else {
            z3 = z;
        }
        if ((i2 & 24576) == 0) {
            z4 = z2;
            i3 |= c0814p.g(z4) ? 16384 : 8192;
        } else {
            z4 = z2;
        }
        if ((196608 & i2) == 0) {
            a3 = a2;
            i3 |= c0814p.f(a3) ? 131072 : 65536;
        } else {
            a3 = a2;
        }
        if ((1572864 & i2) == 0) {
            i3 |= c0814p.h(dVar) ? 1048576 : 524288;
        }
        if ((i3 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1689756685);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.t(new androidx.compose.runtime.internal.d(true, 1184965588, new com.quizlet.assembly.compose.input.f(dVar, 6)));
                c0814p.i0(objI);
            }
            Function2 function2 = (Function2) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1689754646, c0814p, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p.i0(objG);
            }
            c0814p.p(false);
            androidx.compose.animation.E.g(!((Boolean) r23.getValue()).booleanValue(), null, androidx.compose.animation.V.b(null, 13), androidx.compose.animation.V.f(null, 13), null, androidx.compose.runtime.internal.e.e(-812113661, new com.quizlet.features.folders.composables.M(oVar, function12, i4, a3, z4, z3, (InterfaceC0773a0) objG, function2), c0814p), c0814p, 200064, 18);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.F(oVar, i, function1, z, z2, a2, dVar, i2);
        }
    }

    public static final void c(com.quizlet.features.folders.menu.u uVar, com.quizlet.assembly.compose.menu.s sVar, com.quizlet.ui.models.content.listitem.o oVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(334594589);
        int i2 = i | (c0814p.f(uVar) ? 4 : 2) | (c0814p.h(sVar) ? 32 : 16) | (c0814p.h(oVar) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else if (!(uVar instanceof com.quizlet.features.folders.menu.s)) {
            String strD = oVar.d();
            com.quizlet.generated.enums.y1 y1VarB = oVar.b();
            c0814p.X(483881686);
            int i3 = i2 & 7168;
            boolean z = i3 == 2048;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.explanations.questiondetail.ui.composables.l(3, function1);
                c0814p.i0(objI);
            }
            Function2 function2 = (Function2) objI;
            c0814p.p(false);
            c0814p.X(483891286);
            boolean z2 = i3 == 2048;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new androidx.navigation.compose.B(17, function1);
                c0814p.i0(objI2);
            }
            Function1 function12 = (Function1) objI2;
            c0814p.p(false);
            c0814p.X(483894384);
            boolean z3 = i3 == 2048;
            Object objI3 = c0814p.I();
            if (z3 || objI3 == v) {
                objI3 = new com.quizlet.facebook.a(22, function1);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            T4.b(sVar, uVar, strD, y1VarB, function2, function12, (Function0) objI3, null, c0814p, ((i2 >> 3) & 14) | ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(uVar, sVar, oVar, function1, i, 8);
        }
    }

    public static final String d(com.quizlet.ui.models.content.listitem.o oVar) {
        return "item:" + oVar.b().b() + ":" + oVar.d() + ":" + oVar.a();
    }

    public static final String e(float f) {
        if (Float.isNaN(f)) {
            return "NaN";
        }
        if (Float.isInfinite(f)) {
            return f < DefinitionKt.NO_Float_VALUE ? "-Infinity" : "Infinity";
        }
        int iMax = Math.max(1, 0);
        float fPow = (float) Math.pow(10.0f, iMax);
        float f2 = f * fPow;
        int i = (int) f2;
        if (f2 - i >= 0.5f) {
            i++;
        }
        float f3 = i / fPow;
        return iMax > 0 ? String.valueOf(f3) : String.valueOf((int) f3);
    }
}
