package com.google.android.material.elevation;

import android.content.Context;
import android.graphics.Color;
import androidx.annotation.NonNull;
import androidx.core.graphics.d;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class a {
    public static final int f = (int) Math.round(5.1000000000000005d);
    public final boolean a;
    public final int b;
    public final int c;
    public final int d;
    public final float e;

    public a(@NonNull Context context) {
        boolean zC = AbstractC3436c4.c(context, R.attr.elevationOverlayEnabled, false);
        int iC = X3.c(context, R.attr.elevationOverlayColor, 0);
        int iC2 = X3.c(context, R.attr.elevationOverlayAccentColor, 0);
        int iC3 = X3.c(context, R.attr.colorSurface, 0);
        float f2 = context.getResources().getDisplayMetrics().density;
        this.a = zC;
        this.b = iC;
        this.c = iC2;
        this.d = iC3;
        this.e = f2;
    }

    public final int a(float f2, int i) {
        int i2;
        if (!this.a || d.d(i, 255) != this.d) {
            return i;
        }
        float fMin = (this.e <= DefinitionKt.NO_Float_VALUE || f2 <= DefinitionKt.NO_Float_VALUE) ? 0.0f : Math.min(((((float) Math.log1p(f2 / r1)) * 4.5f) + 2.0f) / 100.0f, 1.0f);
        int iAlpha = Color.alpha(i);
        int iE = X3.e(d.d(i, 255), fMin, this.b);
        if (fMin > DefinitionKt.NO_Float_VALUE && (i2 = this.c) != 0) {
            iE = d.b(d.d(i2, f), iE);
        }
        return d.d(iE, iAlpha);
    }
}
