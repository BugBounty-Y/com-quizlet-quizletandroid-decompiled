package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.p3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3513p3 {
    public static final String a(com.quizlet.features.settings.data.models.h hVar, InterfaceC0806l interfaceC0806l) {
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(hVar, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(678508953);
        int iOrdinal = hVar.ordinal();
        if (iOrdinal == 0) {
            i = 1892320888;
            i2 = R.string.change_password_title;
        } else {
            if (iOrdinal != 1) {
                throw com.google.android.gms.measurement.internal.Z.j(1892319514, c0814p, false);
            }
            i = 1892323604;
            i2 = R.string.create_a_password;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static void b(int i, Object[] objArr) {
        for (int i2 = 0; i2 < i; i2++) {
            if (objArr[i2] == null) {
                StringBuilder sb = new StringBuilder(String.valueOf(i2).length() + 9);
                sb.append("at index ");
                sb.append(i2);
                throw new NullPointerException(sb.toString());
            }
        }
    }
}
