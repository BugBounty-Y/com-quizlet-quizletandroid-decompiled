package androidx.constraintlayout.core.motion.utils;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class k {
    public boolean a;
    public float b;
    public float c;

    public final float a() {
        return this.a ? -b(this.c) : b(this.c);
    }

    public final float b(float f) {
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (f > DefinitionKt.NO_Float_VALUE) {
            f -= DefinitionKt.NO_Float_VALUE;
            f2 = DefinitionKt.NO_Float_VALUE;
            if (f >= DefinitionKt.NO_Float_VALUE) {
                float f3 = f - DefinitionKt.NO_Float_VALUE;
                return f3 < DefinitionKt.NO_Float_VALUE ? DefinitionKt.NO_Float_VALUE - ((f3 * DefinitionKt.NO_Float_VALUE) / DefinitionKt.NO_Float_VALUE) : DefinitionKt.NO_Float_VALUE;
            }
        }
        return (((DefinitionKt.NO_Float_VALUE - DefinitionKt.NO_Float_VALUE) * f) / f2) + DefinitionKt.NO_Float_VALUE;
    }
}
