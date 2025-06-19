package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.data.model.AbstractC4178x;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class D {
    public static final void a(int i, int i2, int i3, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String value, String str, Function0 onClearValueAction, Function1 onValueChange) {
        int i4;
        String str2;
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(onValueChange, "onValueChange");
        Intrinsics.checkNotNullParameter(onClearValueAction, "onClearValueAction");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1649702272);
        int i5 = (c0814p.f(value) ? 4 : 2) | i2 | (c0814p.h(onValueChange) ? 32 : 16) | (c0814p.h(onClearValueAction) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        int i6 = i3 & 16;
        if (i6 != 0) {
            i4 = i5 | 24576;
        } else {
            i4 = i5 | (c0814p.f(str) ? 16384 : 8192);
        }
        int i7 = i4 | (c0814p.d(i) ? 131072 : 65536);
        if ((74899 & i7) == 74898 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                str2 = i6 != 0 ? null : str;
            } else {
                c0814p.Q();
                str2 = str;
            }
            c0814p.q();
            b(i, 0, (i7 & 8190) | ((i7 >> 3) & 57344) | ((i7 << 3) & 458752), c0814p, qVar, value, str2, onClearValueAction, onValueChange);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(i, i2, i3, qVar, value, str2, onClearValueAction, onValueChange);
        }
    }

    public static final void b(int i, int i2, int i3, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, Function1 function1) {
        int i4;
        Function1 function12;
        String str3;
        int i5;
        int i6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-495975168);
        if ((i3 & 6) == 0) {
            i4 = (c0814p.f(str) ? 4 : 2) | i3;
        } else {
            i4 = i3;
        }
        if ((i3 & 48) == 0) {
            function12 = function1;
            i4 |= c0814p.h(function12) ? 32 : 16;
        } else {
            function12 = function1;
        }
        if ((i3 & 384) == 0) {
            i4 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i3 & 3072) == 0) {
            i4 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i3 & 24576) == 0) {
            i4 |= c0814p.d(i) ? 16384 : 8192;
        }
        if ((196608 & i3) == 0) {
            str3 = str2;
            i4 |= c0814p.f(str3) ? 131072 : 65536;
        } else {
            str3 = str2;
        }
        int i7 = i4 | 1572864;
        if ((599187 & i7) == 599186 && c0814p.x()) {
            c0814p.Q();
            i6 = i2;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                i5 = 6;
            } else {
                c0814p.Q();
                i5 = i2;
            }
            c0814p.q();
            Object[] objArr = new Object[0];
            c0814p.X(-1174633955);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(22);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            String strD = AbstractC3106b5.d(c0814p, i);
            c0814p.X(-1174624591);
            androidx.compose.runtime.internal.d dVarE = (!((Boolean) interfaceC0773a0.getValue()).booleanValue() || StringsKt.O(str)) ? null : androidx.compose.runtime.internal.e.e(1893633348, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(20, function0), c0814p);
            boolean zR = AbstractC4178x.r(c0814p, false, -1174618796, interfaceC0773a0);
            Object objI2 = c0814p.I();
            if (zR || objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 22);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            AbstractC3745v5.a(str, androidx.compose.ui.focus.a.x(qVar, (Function1) objI2), function12, strD, null, 0, 0, null, null, i5, 6, null, str3, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, dVarE, c0814p, (i7 & 14) | ((i7 << 3) & 896), ((i7 >> 18) & 14) | 48 | ((i7 >> 6) & 7168), 0, 4183024);
            c0814p = c0814p;
            i6 = i5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.b(i, i6, i3, qVar, str, str2, function0, function1);
        }
    }

    public static final com.ionspin.kotlin.bignum.integer.c c() {
        return new com.ionspin.kotlin.bignum.integer.c(10);
    }
}
