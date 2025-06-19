package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String message, com.quizlet.assembly.compose.modals.x xVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function03;
        Function0 function04;
        Intrinsics.checkNotNullParameter(message, "message");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1865608785);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(message) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(xVar) : c0814p.h(xVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            function03 = function0;
            i2 |= c0814p.h(function03) ? 256 : 128;
        } else {
            function03 = function0;
        }
        if ((i & 3072) == 0) {
            function04 = function02;
            i2 |= c0814p.h(function04) ? 2048 : 1024;
        } else {
            function04 = function02;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            com.google.android.gms.internal.mlkit_vision_document_scanner.P5.a(message, null, AbstractC3106b5.d(c0814p, R.string.logout), xVar, AbstractC3106b5.d(c0814p, R.string.logout), function03, AbstractC3106b5.d(c0814p, R.string.cancel), function04, function02, null, c0814p, (i2 & 14) | 4096 | ((i2 << 6) & 7168) | ((i2 << 9) & 458752) | ((i2 << 12) & 29360128) | ((i2 << 15) & 234881024), 514);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(message, xVar, function0, function02, i, 15);
        }
    }

    public static Object b(byte[] bytes, Function1 creator) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        Intrinsics.checkNotNullParameter(creator, "creator");
        Parcel parcelObtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain, "obtain()");
        try {
            parcelObtain.unmarshall(bytes, 0, bytes.length);
            parcelObtain.setDataPosition(0);
            return creator.invoke(parcelObtain);
        } finally {
            parcelObtain.recycle();
        }
    }
}
