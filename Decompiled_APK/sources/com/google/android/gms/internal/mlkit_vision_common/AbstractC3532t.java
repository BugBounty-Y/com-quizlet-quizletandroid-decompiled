package com.google.android.gms.internal.mlkit_vision_common;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3532t {
    public static final /* synthetic */ int a = 0;

    public static float a(float f) {
        return f <= 0.04045f ? f / 12.92f : (float) Math.pow((f + 0.055f) / 1.055f, 2.4000000953674316d);
    }

    public static float b(float f) {
        return f <= 0.0031308f ? f * 12.92f : (float) ((Math.pow(f, 0.4166666567325592d) * 1.0549999475479126d) - 0.054999999701976776d);
    }

    public static int c(int i, float f, int i2) {
        if (i == i2 || f <= DefinitionKt.NO_Float_VALUE) {
            return i;
        }
        if (f >= 1.0f) {
            return i2;
        }
        float f2 = ((i >> 24) & 255) / 255.0f;
        float f3 = ((i2 >> 24) & 255) / 255.0f;
        float fA = a(((i >> 16) & 255) / 255.0f);
        float fA2 = a(((i >> 8) & 255) / 255.0f);
        float fA3 = a((i & 255) / 255.0f);
        float fA4 = a(((i2 >> 16) & 255) / 255.0f);
        float fA5 = a(((i2 >> 8) & 255) / 255.0f);
        float fA6 = a((i2 & 255) / 255.0f);
        float fA7 = android.support.v4.media.session.a.a(f3, f2, f, f2);
        float fA8 = android.support.v4.media.session.a.a(fA4, fA, f, fA);
        float fA9 = android.support.v4.media.session.a.a(fA5, fA2, f, fA2);
        float fA10 = android.support.v4.media.session.a.a(fA6, fA3, f, fA3);
        float fB = b(fA8) * 255.0f;
        float fB2 = b(fA9) * 255.0f;
        return Math.round(b(fA10) * 255.0f) | (Math.round(fB) << 16) | (Math.round(fA7 * 255.0f) << 24) | (Math.round(fB2) << 8);
    }
}
