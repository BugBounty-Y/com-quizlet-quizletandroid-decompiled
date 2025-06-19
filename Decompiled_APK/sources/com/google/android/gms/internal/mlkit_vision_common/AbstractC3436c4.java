package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.util.TypedValue;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.c4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3436c4 {
    public static final String a(com.quizlet.data.model.m2 m2Var, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(886551477);
        if (m2Var == com.quizlet.data.model.m2.a) {
            throw new kotlin.n(null, 1, null);
        }
        if (m2Var == com.quizlet.data.model.m2.b) {
            throw new kotlin.n(null, 1, null);
        }
        if (m2Var != com.quizlet.data.model.m2.c) {
            throw new NoWhenBranchMatchedException();
        }
        String strD = AbstractC3106b5.d(c0814p, R.string.uuf_practice_test_title);
        c0814p.p(false);
        return strD;
    }

    public static TypedValue b(Context context, int i) {
        TypedValue typedValue = new TypedValue();
        if (context.getTheme().resolveAttribute(i, typedValue, true)) {
            return typedValue;
        }
        return null;
    }

    public static boolean c(Context context, int i, boolean z) {
        TypedValue typedValueB = b(context, i);
        return (typedValueB == null || typedValueB.type != 18) ? z : typedValueB.data != 0;
    }

    public static TypedValue d(Context context, String str, int i) {
        TypedValue typedValueB = b(context, i);
        if (typedValueB != null) {
            return typedValueB;
        }
        throw new IllegalArgumentException(String.format("%1$s requires a value for the %2$s attribute to be set in your app theme. You can either set the attribute in your theme or update your theme to inherit from Theme.MaterialComponents (or a descendant).", str, context.getResources().getResourceName(i)));
    }
}
