package androidx.constraintlayout.motion.utils;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class a extends androidx.constraintlayout.motion.widget.l {
    public androidx.constraintlayout.core.motion.utils.k a;

    @Override // androidx.constraintlayout.motion.widget.l
    public final float a() {
        return this.a.a();
    }

    @Override // android.animation.TimeInterpolator
    public final float getInterpolation(float f) {
        float f2;
        androidx.constraintlayout.core.motion.utils.k kVar = this.a;
        kVar.getClass();
        if (f <= DefinitionKt.NO_Float_VALUE) {
            f2 = ((((DefinitionKt.NO_Float_VALUE - DefinitionKt.NO_Float_VALUE) * f) * f) / (DefinitionKt.NO_Float_VALUE * 2.0f)) + (DefinitionKt.NO_Float_VALUE * f);
        } else {
            float f3 = f - DefinitionKt.NO_Float_VALUE;
            if (f3 < DefinitionKt.NO_Float_VALUE) {
                f2 = ((((DefinitionKt.NO_Float_VALUE - DefinitionKt.NO_Float_VALUE) * f3) * f3) / (DefinitionKt.NO_Float_VALUE * 2.0f)) + (DefinitionKt.NO_Float_VALUE * f3) + DefinitionKt.NO_Float_VALUE;
            } else {
                float f4 = f3 - DefinitionKt.NO_Float_VALUE;
                if (f4 <= DefinitionKt.NO_Float_VALUE) {
                    float f5 = DefinitionKt.NO_Float_VALUE * f4;
                    f2 = (DefinitionKt.NO_Float_VALUE + f5) - ((f5 * f4) / (DefinitionKt.NO_Float_VALUE * 2.0f));
                } else {
                    f2 = DefinitionKt.NO_Float_VALUE;
                }
            }
        }
        kVar.b = f2;
        kVar.c = f;
        return kVar.a ? DefinitionKt.NO_Float_VALUE - f2 : DefinitionKt.NO_Float_VALUE + f2;
    }
}
