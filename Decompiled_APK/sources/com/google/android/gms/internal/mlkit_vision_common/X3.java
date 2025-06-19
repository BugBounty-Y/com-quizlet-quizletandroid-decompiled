package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.graphics.Color;
import android.util.TypedValue;
import android.view.View;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class X3 {
    public static final void a(com.quizlet.assembly.compose.modals.x state, com.quizlet.data.model.m2 source, androidx.compose.ui.n nVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1182353666);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(state) : c0814p.h(state) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(source) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function02) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(464937359);
            if (source == com.quizlet.data.model.m2.a) {
                throw new kotlin.n(null, 1, null);
            }
            if (source == com.quizlet.data.model.m2.b) {
                throw new kotlin.n(null, 1, null);
            }
            if (source != com.quizlet.data.model.m2.c) {
                throw new NoWhenBranchMatchedException();
            }
            String strD = AbstractC3106b5.d(c0814p, R.string.uuf_sign_wall_header_practice_tests);
            c0814p.p(false);
            int i4 = i3 << 6;
            Z5.b(state, strD, AbstractC3106b5.d(c0814p, R.string.uuf_sign_wall_sign_up_button), AbstractC3106b5.d(c0814p, R.string.uuf_sign_wall_subheader), AbstractC3106b5.d(c0814p, R.string.uuf_sign_wall_log_in_button), function0, function02, c0814p, ((i3 << 15) & 29360128) | (i3 & 14) | 8 | (458752 & i4) | (i4 & 3670016));
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(state, source, nVar2, function0, function02, i);
        }
    }

    public static int b(int i, View view) {
        Context context = view.getContext();
        TypedValue typedValueD = AbstractC3436c4.d(view.getContext(), view.getClass().getCanonicalName(), i);
        int i2 = typedValueD.resourceId;
        return i2 != 0 ? context.getColor(i2) : typedValueD.data;
    }

    public static int c(Context context, int i, int i2) {
        Integer numValueOf;
        TypedValue typedValueB = AbstractC3436c4.b(context, i);
        if (typedValueB != null) {
            int i3 = typedValueB.resourceId;
            numValueOf = Integer.valueOf(i3 != 0 ? context.getColor(i3) : typedValueB.data);
        } else {
            numValueOf = null;
        }
        return numValueOf != null ? numValueOf.intValue() : i2;
    }

    public static boolean d(int i) {
        if (i == 0) {
            return false;
        }
        ThreadLocal threadLocal = androidx.core.graphics.d.a;
        double[] dArr = (double[]) threadLocal.get();
        if (dArr == null) {
            dArr = new double[3];
            threadLocal.set(dArr);
        }
        int iRed = Color.red(i);
        int iGreen = Color.green(i);
        int iBlue = Color.blue(i);
        if (dArr.length != 3) {
            throw new IllegalArgumentException("outXyz must have a length of 3.");
        }
        double d = iRed / 255.0d;
        double dPow = d < 0.04045d ? d / 12.92d : Math.pow((d + 0.055d) / 1.055d, 2.4d);
        double d2 = iGreen / 255.0d;
        double dPow2 = d2 < 0.04045d ? d2 / 12.92d : Math.pow((d2 + 0.055d) / 1.055d, 2.4d);
        double d3 = iBlue / 255.0d;
        double dPow3 = d3 < 0.04045d ? d3 / 12.92d : Math.pow((d3 + 0.055d) / 1.055d, 2.4d);
        dArr[0] = ((0.1805d * dPow3) + (0.3576d * dPow2) + (0.4124d * dPow)) * 100.0d;
        double d4 = ((0.0722d * dPow3) + (0.7152d * dPow2) + (0.2126d * dPow)) * 100.0d;
        dArr[1] = d4;
        dArr[2] = ((dPow3 * 0.9505d) + (dPow2 * 0.1192d) + (dPow * 0.0193d)) * 100.0d;
        return d4 / 100.0d > 0.5d;
    }

    public static int e(int i, float f, int i2) {
        return androidx.core.graphics.d.b(androidx.core.graphics.d.d(i2, Math.round(Color.alpha(i2) * f)), i);
    }
}
