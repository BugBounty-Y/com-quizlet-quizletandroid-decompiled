package com.google.android.material.animation;

import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;

/* loaded from: classes2.dex */
public abstract class a {
    public static final LinearInterpolator a = new LinearInterpolator();
    public static final androidx.interpolator.view.animation.a b = new androidx.interpolator.view.animation.a(1);
    public static final androidx.interpolator.view.animation.a c = new androidx.interpolator.view.animation.a(0);
    public static final androidx.interpolator.view.animation.a d = new androidx.interpolator.view.animation.a(androidx.interpolator.view.animation.a.e);
    public static final DecelerateInterpolator e = new DecelerateInterpolator();

    public static float a(float f, float f2, float f3) {
        return android.support.v4.media.session.a.a(f2, f, f3, f);
    }

    public static float b(float f, float f2, float f3, float f4, float f5) {
        return f5 <= f3 ? f : f5 >= f4 ? f2 : a(f, f2, (f5 - f3) / (f4 - f3));
    }

    public static int c(int i, float f, int i2) {
        return Math.round(f * (i2 - i)) + i;
    }
}
