package com.google.android.material.bottomappbar;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class g extends com.google.android.material.shape.e implements Cloneable {
    public float b;
    public float c;
    public float d;
    public float e;
    public float f;
    public float g;

    @Override // com.google.android.material.shape.e
    public final void t(float f, float f2, float f3, com.airbnb.lottie.value.b bVar) {
        float f4;
        float f5;
        float f6 = this.d;
        if (f6 == DefinitionKt.NO_Float_VALUE) {
            bVar.d(f, DefinitionKt.NO_Float_VALUE);
            return;
        }
        float f7 = ((this.c * 2.0f) + f6) / 2.0f;
        float f8 = f3 * this.b;
        float f9 = f2 + this.f;
        float fA = android.support.v4.media.session.a.a(1.0f, f3, f7, this.e * f3);
        if (fA / f7 >= 1.0f) {
            bVar.d(f, DefinitionKt.NO_Float_VALUE);
            return;
        }
        float f10 = this.g;
        float f11 = f10 * f3;
        boolean z = f10 == -1.0f || Math.abs((f10 * 2.0f) - f6) < 0.1f;
        if (z) {
            f4 = fA;
            f5 = 0.0f;
        } else {
            f5 = 1.75f;
            f4 = 0.0f;
        }
        float f12 = f7 + f8;
        float f13 = f4 + f8;
        float fSqrt = (float) Math.sqrt((f12 * f12) - (f13 * f13));
        float f14 = f9 - fSqrt;
        float f15 = f9 + fSqrt;
        float degrees = (float) Math.toDegrees(Math.atan(fSqrt / f13));
        float f16 = (90.0f - degrees) + f5;
        bVar.d(f14, DefinitionKt.NO_Float_VALUE);
        float f17 = f14 - f8;
        float f18 = f14 + f8;
        float f19 = f8 * 2.0f;
        bVar.a(f17, DefinitionKt.NO_Float_VALUE, f18, f19, 270.0f, degrees);
        if (z) {
            bVar.a(f9 - f7, (-f7) - f4, f9 + f7, f7 - f4, 180.0f - f16, (f16 * 2.0f) - 180.0f);
        } else {
            float f20 = this.c;
            float f21 = f11 * 2.0f;
            float f22 = f20 + f21;
            float f23 = f9 - f7;
            bVar.a(f23, -(f11 + f20), f22 + f23, f20 + f11, 180.0f - f16, ((f16 * 2.0f) - 180.0f) / 2.0f);
            float f24 = f9 + f7;
            float f25 = this.c;
            bVar.d(f24 - ((f25 / 2.0f) + f11), f25 + f11);
            float f26 = this.c;
            bVar.a(f24 - (f21 + f26), -(f11 + f26), f24, f26 + f11, 90.0f, f16 - 90.0f);
        }
        bVar.a(f15 - f8, DefinitionKt.NO_Float_VALUE, f15 + f8, f19, 270.0f - degrees, degrees);
        bVar.d(f, DefinitionKt.NO_Float_VALUE);
    }

    public final void y(float f) {
        if (f < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("cradleVerticalOffset must be positive.");
        }
        this.e = f;
    }
}
