package com.google.android.material.floatingactionbutton;

import android.animation.FloatEvaluator;
import android.animation.TypeEvaluator;
import android.graphics.Rect;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class m implements TypeEvaluator {
    public final /* synthetic */ int a = 0;
    public Object b;

    public /* synthetic */ m() {
    }

    @Override // android.animation.TypeEvaluator
    public final Object evaluate(float f, Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                float fFloatValue = ((FloatEvaluator) this.b).evaluate(f, (Number) obj, (Number) obj2).floatValue();
                if (fFloatValue < 0.1f) {
                    fFloatValue = DefinitionKt.NO_Float_VALUE;
                }
                return Float.valueOf(fFloatValue);
            default:
                Rect rect = (Rect) obj;
                Rect rect2 = (Rect) obj2;
                int i = rect.left + ((int) ((rect2.left - r0) * f));
                int i2 = rect.top + ((int) ((rect2.top - r1) * f));
                int i3 = rect.right + ((int) ((rect2.right - r2) * f));
                int i4 = rect.bottom + ((int) ((rect2.bottom - r6) * f));
                Rect rect3 = (Rect) this.b;
                rect3.set(i, i2, i3, i4);
                return rect3;
        }
    }

    public m(Rect rect) {
        this.b = rect;
    }
}
