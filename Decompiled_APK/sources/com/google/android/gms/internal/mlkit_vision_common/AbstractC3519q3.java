package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0814p;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.q3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3519q3 {
    public static final String a(com.quizlet.features.settings.data.models.b bVar, C0814p c0814p) {
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        c0814p.X(-2061407194);
        int iOrdinal = bVar.ordinal();
        if (iOrdinal == 0) {
            i = 1857919062;
            i2 = R.string.change_username_title;
        } else if (iOrdinal == 1) {
            i = 1857921971;
            i2 = R.string.update_email_title;
        } else if (iOrdinal == 2) {
            i = 1857925078;
            i2 = R.string.change_password_title;
        } else {
            if (iOrdinal != 3) {
                throw com.google.android.gms.measurement.internal.Z.j(1857917612, c0814p, false);
            }
            i = 1857928274;
            i2 = R.string.create_a_password;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static Object b(Class cls, String str, androidx.work.impl.model.e... eVarArr) {
        int length = eVarArr.length;
        Class<?>[] clsArr = new Class[length];
        Object[] objArr = new Object[length];
        for (int i = 0; i < eVarArr.length; i++) {
            androidx.work.impl.model.e eVar = eVarArr[i];
            eVar.getClass();
            clsArr[i] = (Class) eVar.b;
            objArr[i] = eVarArr[i].c;
        }
        return cls.getDeclaredMethod(str, clsArr).invoke(null, objArr);
    }
}
