package com.google.android.material.internal;

import android.animation.TimeInterpolator;
import android.view.animation.Interpolator;

/* loaded from: classes2.dex */
public final class j implements TimeInterpolator {
    public final Interpolator a;

    public j(Interpolator interpolator) {
        this.a = interpolator;
    }

    public static TimeInterpolator a(boolean z, Interpolator interpolator) {
        return z ? interpolator : new j(interpolator);
    }

    @Override // android.animation.TimeInterpolator
    public final float getInterpolation(float f) {
        return 1.0f - this.a.getInterpolation(f);
    }
}
