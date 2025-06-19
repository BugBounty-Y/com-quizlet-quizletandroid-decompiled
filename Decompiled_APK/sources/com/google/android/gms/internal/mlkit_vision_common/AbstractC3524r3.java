package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.r3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3524r3 {
    public static final String a(com.quizlet.themes.nighttheme.a aVar, InterfaceC0806l interfaceC0806l) {
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1771209302);
        int iOrdinal = aVar.ordinal();
        if (iOrdinal == 0) {
            i = 1996035313;
            i2 = R.string.system_theme_mode;
        } else if (iOrdinal == 1) {
            i = 1996037904;
            i2 = R.string.light_theme_mode;
        } else {
            if (iOrdinal != 2) {
                throw com.google.android.gms.measurement.internal.Z.j(1996033892, c0814p, false);
            }
            i = 1996040431;
            i2 = R.string.dark_theme_mode;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static void b(int i, int i2) {
        String strB;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strB = AbstractC3530s3.b("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    StringBuilder sb = new StringBuilder(String.valueOf(i2).length() + 15);
                    sb.append("negative size: ");
                    sb.append(i2);
                    throw new IllegalArgumentException(sb.toString());
                }
                strB = AbstractC3530s3.b("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strB);
        }
    }

    public static void c(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(e(i, i2, "index"));
        }
    }

    public static void d(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? e(i, i3, "start index") : (i2 < 0 || i2 > i3) ? e(i2, i3, "end index") : AbstractC3530s3.b("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static String e(int i, int i2, String str) {
        if (i < 0) {
            return AbstractC3530s3.b("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return AbstractC3530s3.b("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        StringBuilder sb = new StringBuilder(String.valueOf(i2).length() + 15);
        sb.append("negative size: ");
        sb.append(i2);
        throw new IllegalArgumentException(sb.toString());
    }
}
