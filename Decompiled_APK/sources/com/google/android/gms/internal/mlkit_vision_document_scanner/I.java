package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class I {
    public static final void a(String value, Function1 onValueChange, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(onValueChange, "onValueChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-308669394);
        int i2 = i | (c0814p2.f(value) ? 4 : 2) | (c0814p2.h(onValueChange) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128) | (c0814p2.h(function0) ? 2048 : 1024) | (c0814p2.h(function02) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(103683863);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(23);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p2, 3072, 6);
            String strD = AbstractC3106b5.d(c0814p2, R.string.signup_password_input_label);
            c0814p2.X(103694637);
            androidx.compose.runtime.internal.d dVarE = (!((Boolean) interfaceC0773a0.getValue()).booleanValue() || StringsKt.O(value)) ? null : androidx.compose.runtime.internal.e.e(-2136881557, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(21, function0), c0814p2);
            boolean zR = AbstractC4178x.r(c0814p2, false, 103701479, interfaceC0773a0);
            Object objI2 = c0814p2.I();
            if (zR || objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 23);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.a(value, androidx.compose.ui.focus.a.x(qVar, (Function1) objI2), onValueChange, strD, null, 0, 0, null, null, 7, 7, function02, null, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, dVarE, c0814p, (i2 & 14) | ((i2 << 3) & 896), ((i2 >> 6) & 896) | 54, 0, 4187120);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(value, onValueChange, qVar, function0, function02, i);
        }
    }

    public static final void b(okio.t tVar, okio.x dir) {
        Intrinsics.checkNotNullParameter(tVar, "<this>");
        Intrinsics.checkNotNullParameter(dir, "dir");
        Iterator it2 = ((ArrayList) tVar.q(dir)).iterator();
        while (it2.hasNext()) {
            okio.x fileOrDirectory = (okio.x) it2.next();
            Intrinsics.checkNotNullParameter(fileOrDirectory, "fileOrDirectory");
            Intrinsics.checkNotNullParameter(fileOrDirectory, "fileOrDirectory");
            Intrinsics.checkNotNullParameter(tVar, "<this>");
            Intrinsics.checkNotNullParameter(fileOrDirectory, "fileOrDirectory");
            okio.internal.d block = new okio.internal.d(tVar, fileOrDirectory, null);
            Intrinsics.checkNotNullParameter(block, "block");
            kotlin.sequences.h hVarA = kotlin.sequences.j.a(block);
            while (hVarA.hasNext()) {
                tVar.l((okio.x) hVarA.next(), false);
            }
        }
    }
}
