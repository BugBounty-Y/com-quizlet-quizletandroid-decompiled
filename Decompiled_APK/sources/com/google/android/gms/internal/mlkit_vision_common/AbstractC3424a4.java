package com.google.android.gms.internal.mlkit_vision_common;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.a4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3424a4 {
    public static final /* synthetic */ int a = 0;

    public static float a(float f, float f2, float f3, float f4) {
        return (float) Math.hypot(f3 - f, f4 - f2);
    }

    public static float b(float f, float f2, float f3, float f4) {
        float fA = a(f, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        float fA2 = a(f, f2, f3, DefinitionKt.NO_Float_VALUE);
        float fA3 = a(f, f2, f3, f4);
        float fA4 = a(f, f2, DefinitionKt.NO_Float_VALUE, f4);
        return (fA <= fA2 || fA <= fA3 || fA <= fA4) ? (fA2 <= fA3 || fA2 <= fA4) ? fA3 > fA4 ? fA3 : fA4 : fA2 : fA;
    }
}
