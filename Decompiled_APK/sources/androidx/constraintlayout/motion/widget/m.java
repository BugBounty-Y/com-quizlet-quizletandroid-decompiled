package androidx.constraintlayout.motion.widget;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class m extends l {
    public final float a = DefinitionKt.NO_Float_VALUE;
    public final float b = DefinitionKt.NO_Float_VALUE;
    public final /* synthetic */ r c;

    public m(r rVar) {
        this.c = rVar;
    }

    @Override // androidx.constraintlayout.motion.widget.l
    public final float a() {
        return this.c.s;
    }

    @Override // android.animation.TimeInterpolator
    public final float getInterpolation(float f) {
        float f2 = this.a;
        r rVar = this.c;
        if (f2 > DefinitionKt.NO_Float_VALUE) {
            if (f2 / DefinitionKt.NO_Float_VALUE < f) {
                f = f2 / DefinitionKt.NO_Float_VALUE;
            }
            rVar.s = f2 - (DefinitionKt.NO_Float_VALUE * f);
            return ((f2 * f) - (((DefinitionKt.NO_Float_VALUE * f) * f) / 2.0f)) + this.b;
        }
        if ((-f2) / DefinitionKt.NO_Float_VALUE < f) {
            f = (-f2) / DefinitionKt.NO_Float_VALUE;
        }
        rVar.s = (DefinitionKt.NO_Float_VALUE * f) + f2;
        return (((DefinitionKt.NO_Float_VALUE * f) * f) / 2.0f) + (f2 * f) + this.b;
    }
}
