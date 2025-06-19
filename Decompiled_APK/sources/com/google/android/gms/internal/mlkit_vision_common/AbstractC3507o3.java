package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.settings.viewmodels.C4447e;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.o3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3507o3 {
    public static final void a(String str, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-437991592);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            N2.b(null, str, 0L, null, function0, androidx.compose.runtime.internal.e.e(-2018247560, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(18, function02), c0814p), c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 196608 | ((i2 << 9) & 57344), 13);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 18, str, function0, function02);
        }
    }

    public static final void b(com.quizlet.features.settings.data.models.h hVar, com.quizlet.features.settings.data.states.h hVar2, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        String str4;
        Function1 function14;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-304353946);
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
            i2 |= c0814p2.h(function0) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p2.h(function02) ? 536870912 : 268435456;
        }
        if ((i2 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(-1639981790, new com.quizlet.assembly.compose.menu.l(hVar, function0, function02, 24), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(1928888503, new com.quizlet.features.settings.composables.updatepassword.d(hVar, hVar2, str2, function12, str4, function14, str, function1, 1), c0814p2), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.updatepassword.c(hVar, hVar2, str, function1, str2, function12, str3, function13, function0, function02, i, 1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void c(com.quizlet.features.settings.data.models.h updatePasswordType, com.quizlet.features.settings.viewmodels.q viewModel, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
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
        c0814p.Z(156331840);
        int i3 = i | (c0814p.f(viewModel) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj2 = C0804k.a;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(viewModel.a(), c0814p);
            Object[] objArr = new Object[0];
            c0814p.X(1464758937);
            Object objI = c0814p.I();
            if (objI == obj2) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(7);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(1464760953);
            Object objI2 = c0814p.I();
            if (objI2 == obj2) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.c(8);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p.X(1464763097);
            Object objI3 = c0814p.I();
            if (objI3 == obj2) {
                objI3 = new com.quizlet.features.settings.composables.changeusername.c(9);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a07 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr3, null, (Function0) objI3, c0814p, 3072, 6);
            c0814p.X(1464764893);
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
                aVar = new com.quizlet.features.settings.composables.updatepassword.a(viewModel, interfaceC0773a0, interfaceC0773a04, interfaceC0773a02, 2);
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
            c0814p.X(1464774227);
            boolean z3 = (i2 & 896) == 256 ? true : z;
            Object objI5 = c0814p.I();
            if (z3 || objI5 == obj) {
                objI5 = new com.quizlet.features.settings.composables.updatepassword.j(function0, null);
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
                objI6 = new com.quizlet.features.settings.composables.updatepassword.i(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            com.quizlet.features.settings.data.states.h hVar = (com.quizlet.features.settings.data.states.h) AbstractC4178x.k(unit, (Function2) objI6, c0814p, false, interfaceC0773a03);
            String str = (String) interfaceC0773a0.getValue();
            c0814p.X(1464780173);
            boolean zF = c0814p.f(interfaceC0773a0) | c0814p.f(function02);
            Object objI7 = c0814p.I();
            if (zF || objI7 == obj) {
                objI7 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a0, 5);
                c0814p.i0(objI7);
            }
            Function1 function1 = (Function1) objI7;
            c0814p.p(false);
            String str2 = (String) interfaceC0773a04.getValue();
            c0814p.X(1464784681);
            boolean zF2 = c0814p.f(interfaceC0773a04) | c0814p.f(function02);
            Object objI8 = c0814p.I();
            if (zF2 || objI8 == obj) {
                objI8 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a04, 6);
                c0814p.i0(objI8);
            }
            Function1 function12 = (Function1) objI8;
            c0814p.p(false);
            String str3 = (String) interfaceC0773a02.getValue();
            c0814p.X(1464789453);
            boolean zF3 = c0814p.f(interfaceC0773a02) | c0814p.f(function02);
            Object objI9 = c0814p.I();
            if (zF3 || objI9 == obj) {
                objI9 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a02, 7);
                c0814p.i0(objI9);
            }
            Function1 function13 = (Function1) objI9;
            boolean zR = AbstractC4178x.r(c0814p, false, 1464793816, interfaceC0773a0) | c0814p.f(interfaceC0773a04) | c0814p.f(interfaceC0773a02) | (i4 == 32);
            Object objI10 = c0814p.I();
            if (zR || objI10 == obj) {
                Object aVar2 = new com.quizlet.features.settings.composables.updatepassword.a(viewModel, interfaceC0773a0, interfaceC0773a04, interfaceC0773a02, 3);
                c0814p.i0(aVar2);
                objI10 = aVar2;
            }
            c0814p.p(false);
            b(updatePasswordType, hVar, str, function1, str2, function12, str3, function13, function0, (Function0) objI10, c0814p, ((i2 << 18) & 234881024) | 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.updatepassword.b(updatePasswordType, viewModel, function0, i, 1);
        }
    }

    public static int d(int i) {
        int[] iArr = {1, 2, 3};
        for (int i2 = 0; i2 < 3; i2++) {
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
