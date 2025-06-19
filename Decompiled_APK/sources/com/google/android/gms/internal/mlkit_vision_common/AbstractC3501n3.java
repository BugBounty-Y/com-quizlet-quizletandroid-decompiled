package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.settings.viewmodels.C4447e;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.n3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3501n3 {
    public static final void a(com.quizlet.features.settings.data.models.h hVar, com.quizlet.features.settings.data.states.h hVar2, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        String str4;
        Function1 function14;
        Function0 function03;
        Function0 function04;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-353697077);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(hVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p2.f(hVar2) : c0814p2.h(hVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(str2) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function12) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            str4 = str3;
            i2 |= c0814p2.f(str4) ? 1048576 : 524288;
        } else {
            str4 = str3;
        }
        if ((12582912 & i) == 0) {
            function14 = function13;
            i2 |= c0814p2.h(function14) ? 8388608 : 4194304;
        } else {
            function14 = function13;
        }
        if ((100663296 & i) == 0) {
            function03 = function0;
            i2 |= c0814p2.h(function03) ? 67108864 : 33554432;
        } else {
            function03 = function0;
        }
        if ((805306368 & i) == 0) {
            function04 = function02;
            i2 |= c0814p2.h(function04) ? 536870912 : 268435456;
        } else {
            function04 = function02;
        }
        if ((i2 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(865478755, new com.quizlet.features.setpage.termlist.ui.j(hVar, hVar2, str2, function12, str4, function14, str, function1, function04, function03), c0814p2);
            c0814p = c0814p2;
            S5.a(null, 0L, DefinitionKt.NO_Float_VALUE, 0L, null, dVarE, c0814p, 196608, 31);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.updatepassword.c(hVar, hVar2, str, function1, str2, function12, str3, function13, function0, function02, i, 0);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void b(com.quizlet.features.settings.data.models.h updatePasswordType, com.quizlet.features.settings.viewmodels.q viewModel, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Object aVar;
        Object obj;
        InterfaceC0773a0 interfaceC0773a0;
        boolean z;
        InterfaceC0773a0 interfaceC0773a02;
        InterfaceC0773a0 interfaceC0773a03;
        InterfaceC0773a0 interfaceC0773a04;
        Intrinsics.checkNotNullParameter(updatePasswordType, "updatePasswordType");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1573905138);
        int i3 = i | (c0814p.f(viewModel) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj2 = C0804k.a;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(viewModel.a(), c0814p);
            Object[] objArr = new Object[0];
            c0814p.X(-1365417072);
            Object objI = c0814p.I();
            if (objI == obj2) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(4);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-1365415056);
            Object objI2 = c0814p.I();
            if (objI2 == obj2) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.c(5);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p.X(-1365412912);
            Object objI3 = c0814p.I();
            if (objI3 == obj2) {
                objI3 = new com.quizlet.features.settings.composables.changeusername.c(6);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a07 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr3, null, (Function0) objI3, c0814p, 3072, 6);
            c0814p.X(-1365411116);
            int i4 = i3 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z2 = i4 == 32;
            Object objI4 = c0814p.I();
            if (z2 || objI4 == obj2) {
                i2 = i3;
                obj = obj2;
                interfaceC0773a0 = interfaceC0773a05;
                z = false;
                interfaceC0773a02 = interfaceC0773a07;
                interfaceC0773a03 = interfaceC0773a0M;
                interfaceC0773a04 = interfaceC0773a06;
                aVar = new com.quizlet.features.settings.composables.updatepassword.a(viewModel, interfaceC0773a0, interfaceC0773a04, interfaceC0773a02, 0);
                c0814p.i0(aVar);
            } else {
                z = false;
                interfaceC0773a02 = interfaceC0773a07;
                i2 = i3;
                interfaceC0773a03 = interfaceC0773a0M;
                aVar = objI4;
                interfaceC0773a04 = interfaceC0773a06;
                obj = obj2;
                interfaceC0773a0 = interfaceC0773a05;
            }
            Function0 function02 = (Function0) aVar;
            c0814p.p(z);
            kotlinx.coroutines.flow.d0 d0Var = ((C4447e) viewModel).b;
            c0814p.X(-1365401782);
            boolean z3 = (i2 & 896) == 256 ? true : z;
            Object objI5 = c0814p.I();
            if (z3 || objI5 == obj) {
                objI5 = new com.quizlet.features.settings.composables.updatepassword.g(function0, null);
                c0814p.i0(objI5);
            }
            c0814p.p(z);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            Object obj3 = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI5, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(obj3) | c0814p.f(interfaceC0773a0D);
            Object objI6 = c0814p.I();
            if (zH || objI6 == obj) {
                objI6 = new com.quizlet.features.settings.composables.updatepassword.f(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            com.quizlet.features.settings.data.states.h hVar = (com.quizlet.features.settings.data.states.h) AbstractC4178x.k(unit, (Function2) objI6, c0814p, false, interfaceC0773a03);
            String str = (String) interfaceC0773a0.getValue();
            c0814p.X(-1365395836);
            boolean zF = c0814p.f(interfaceC0773a0) | c0814p.f(function02);
            Object objI7 = c0814p.I();
            if (zF || objI7 == obj) {
                objI7 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a0, 2);
                c0814p.i0(objI7);
            }
            Function1 function1 = (Function1) objI7;
            c0814p.p(false);
            String str2 = (String) interfaceC0773a04.getValue();
            c0814p.X(-1365391328);
            boolean zF2 = c0814p.f(interfaceC0773a04) | c0814p.f(function02);
            Object objI8 = c0814p.I();
            if (zF2 || objI8 == obj) {
                objI8 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a04, 3);
                c0814p.i0(objI8);
            }
            Function1 function12 = (Function1) objI8;
            c0814p.p(false);
            String str3 = (String) interfaceC0773a02.getValue();
            c0814p.X(-1365386556);
            boolean zF3 = c0814p.f(interfaceC0773a02) | c0814p.f(function02);
            Object objI9 = c0814p.I();
            if (zF3 || objI9 == obj) {
                objI9 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a02, 4);
                c0814p.i0(objI9);
            }
            Function1 function13 = (Function1) objI9;
            boolean zR = AbstractC4178x.r(c0814p, false, -1365382193, interfaceC0773a0) | c0814p.f(interfaceC0773a04) | c0814p.f(interfaceC0773a02) | (i4 == 32);
            Object objI10 = c0814p.I();
            if (zR || objI10 == obj) {
                Object aVar2 = new com.quizlet.features.settings.composables.updatepassword.a(viewModel, interfaceC0773a0, interfaceC0773a04, interfaceC0773a02, 1);
                c0814p.i0(aVar2);
                objI10 = aVar2;
            }
            c0814p.p(false);
            a(updatePasswordType, hVar, str, function1, str2, function12, str3, function13, function0, (Function0) objI10, c0814p, ((i2 << 18) & 234881024) | 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.updatepassword.b(updatePasswordType, viewModel, function0, i, 0);
        }
    }

    public static int c(int i) {
        int[] iArr = {1, 2, 3, 4, 5, 6};
        for (int i2 = 0; i2 < 6; i2++) {
            int i3 = iArr[i2];
            int i4 = i3 - 1;
            if (i3 == 0) {
                throw null;
            }
            if (i4 == i) {
                return i3;
            }
        }
        return 1;
    }
}
