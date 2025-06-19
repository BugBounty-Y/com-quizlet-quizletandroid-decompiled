package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.animation.C0281h;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;

/* loaded from: classes2.dex */
public abstract class L4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.n nVar, boolean z, androidx.compose.ui.focus.h hVar, int i, Function1 function1, Function0 function0, Function1 function12, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.n nVar2;
        InterfaceC0773a0 interfaceC0773a0;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        int i4 = 0;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1317307839);
        int i5 = i2 | 6 | (c0814p2.f(null) ? 32 : 16) | (c0814p2.g(z) ? 256 : 128) | (c0814p2.h(hVar) ? 2048 : 1024) | (c0814p2.d(i) ? 16384 : 8192) | (c0814p2.h(function1) ? 131072 : 65536) | (c0814p2.h(function0) ? 1048576 : 524288) | (c0814p2.h(function12) ? 8388608 : 4194304);
        if ((i5 & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i6 = i2 & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i6 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            c0814p2.X(-429558993);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = C0776c.z("");
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-429557171, c0814p2, false);
            if (objG == v) {
                objG = new androidx.compose.ui.focus.p();
                c0814p2.i0(objG);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objG;
            c0814p2.p(false);
            c0814p2.X(-429555974);
            c0814p2.p(false);
            c0814p2.X(-429551377);
            if (z) {
                Unit unit = Unit.a;
                c0814p2.X(-429549275);
                Object objI2 = c0814p2.I();
                if (objI2 == v) {
                    objI2 = new com.quizlet.features.folders.composables.E(pVar, null);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                C0776c.f(c0814p2, unit, (Function2) objI2);
            }
            c0814p2.p(false);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).j;
            androidx.compose.ui.q qVarK = androidx.compose.ui.focus.a.k(androidx.compose.foundation.layout.K0.c(nVar2, 1.0f), pVar);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.y(qVarK, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, 11), "search_bar");
            String str = (String) interfaceC0773a02.getValue();
            mVar.d();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g);
            C0490g0 c0490g0 = new C0490g0(0, 3, 119);
            c0814p2.X(-429518857);
            boolean zH = ((i5 & 29360128) == 8388608) | c0814p2.h(hVar);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == v) {
                objI3 = new com.quizlet.features.folders.composables.D(function12, hVar, interfaceC0773a02, i4);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            C0488f0 c0488f0 = new C0488f0((Function1) null, (Function1) null, (Function1) null, (Function1) objI3, (Function1) null, 47);
            androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
            long j = C0861v.f;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jH = ((com.quizlet.themes.b) c0814p2.j(b)).b.h();
            long jH2 = ((com.quizlet.themes.b) c0814p2.j(b)).b.h();
            androidx.compose.ui.n nVar4 = nVar2;
            androidx.compose.material3.A4 a4C = androidx.compose.material3.D4.c(0L, 0L, 0L, 0L, jH, jH2, 0L, 0L, 0L, 0L, null, j, j, j, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, c0814p2, 2147469263);
            c0814p2.X(-429525766);
            boolean z2 = (i5 & 458752) == 131072;
            Object objI4 = c0814p2.I();
            if (z2 || objI4 == v) {
                interfaceC0773a0 = interfaceC0773a02;
                i3 = 2;
                objI4 = new com.quizlet.features.flashcards.settings.ui.e(i3, interfaceC0773a0, function1);
                c0814p2.i0(objI4);
            } else {
                interfaceC0773a0 = interfaceC0773a02;
                i3 = 2;
            }
            c0814p2.p(false);
            androidx.compose.material3.K4.b(str, (Function1) objI4, qVarG, false, false, l, null, androidx.compose.runtime.internal.e.e(242626150, new com.quizlet.assembly.compose.modals.r(i, i3), c0814p2), null, androidx.compose.runtime.internal.e.e(2000253288, new com.quizlet.features.folders.composables.F(function0, interfaceC0773a0, 0), c0814p2), null, false, null, c0490g0, c0488f0, true, 0, 0, null, dVarA, a4C, c0814p2, 817889280, 12779520, 0, 1867096);
            c0814p = c0814p2;
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.diagrams.ui.f(nVar3, z, hVar, i, function1, function0, function12, i2);
        }
    }

    public static final String b(Object obj) {
        return obj + " cannot be saved using the current SaveableStateRegistry. The default implementation only supports types which can be stored inside the Bundle. Please consider implementing a custom Saver for this class and pass it to rememberSaveable().";
    }

    public static final InterfaceC0773a0 c(Object[] objArr, com.quizlet.data.repository.explanations.myexplanations.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l) {
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.e(aVar, "null cannot be cast to non-null type androidx.compose.runtime.saveable.Saver<T of androidx.compose.runtime.saveable.RememberSaveableKt.mutableStateSaver, kotlin.Any>");
        C0281h c0281h = new C0281h(aVar, 24);
        C0775b0 c0775b0 = new C0775b0(aVar, 6);
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = androidx.compose.runtime.saveable.m.a;
        return (InterfaceC0773a0) d(objArrCopyOf, new com.quizlet.data.repository.explanations.myexplanations.a(c0281h, false, c0775b0, 3), function0, interfaceC0806l, 0, 0);
    }

    public static final Object d(Object[] objArr, com.quizlet.data.repository.explanations.myexplanations.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Object[] objArr2;
        Object obj;
        Object objC;
        if ((i2 & 2) != 0) {
            aVar = androidx.compose.runtime.saveable.m.a;
        }
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = aVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        String string = Integer.toString(c0814p.P, CharsKt.checkRadix(36));
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        Intrinsics.e(aVar2, "null cannot be cast to non-null type androidx.compose.runtime.saveable.Saver<T of androidx.compose.runtime.saveable.RememberSaveableKt.rememberSaveable, kotlin.Any>");
        androidx.compose.runtime.saveable.i iVar = (androidx.compose.runtime.saveable.i) c0814p.j(androidx.compose.runtime.saveable.k.a);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            Object objInvoke = (iVar == null || (objC = iVar.c(string)) == null) ? null : ((Function1) aVar2.c).invoke(objC);
            if (objInvoke == null) {
                objInvoke = function0.invoke();
            }
            objArr2 = objArr;
            androidx.compose.runtime.saveable.b bVar = new androidx.compose.runtime.saveable.b(aVar2, iVar, string, objInvoke, objArr2);
            c0814p.i0(bVar);
            objI = bVar;
        } else {
            objArr2 = objArr;
        }
        androidx.compose.runtime.saveable.b bVar2 = (androidx.compose.runtime.saveable.b) objI;
        Object objInvoke2 = Arrays.equals(objArr2, bVar2.e) ? bVar2.d : null;
        if (objInvoke2 == null) {
            objInvoke2 = function0.invoke();
        }
        boolean zH = c0814p.h(bVar2) | c0814p.h(aVar2) | c0814p.h(iVar) | c0814p.f(string) | c0814p.h(objInvoke2) | c0814p.h(objArr2);
        Object objI2 = c0814p.I();
        if (zH || objI2 == v) {
            Object[] objArr3 = objArr2;
            obj = objInvoke2;
            androidx.compose.runtime.saveable.a aVar3 = new androidx.compose.runtime.saveable.a(bVar2, aVar2, iVar, string, obj, objArr3);
            c0814p.i0(aVar3);
            objI2 = aVar3;
        } else {
            obj = objInvoke2;
        }
        C0776c.i((Function0) objI2, c0814p);
        return obj;
    }
}
