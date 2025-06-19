package com.google.android.material.shape;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class d extends AbstractC3460g4 {
    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4
    public final void a(com.airbnb.lottie.value.b bVar, float f, float f2) {
        bVar.e(f2 * f, 180.0f, 90.0f);
        double d = f2;
        double d2 = f;
        bVar.d((float) (Math.sin(Math.toRadians(90.0f)) * d * d2), (float) (Math.sin(Math.toRadians(DefinitionKt.NO_Float_VALUE)) * d * d2));
    }
}
