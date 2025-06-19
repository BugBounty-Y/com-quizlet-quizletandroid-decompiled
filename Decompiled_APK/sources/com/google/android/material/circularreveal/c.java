package com.google.android.material.circularreveal;

import android.animation.TypeEvaluator;

/* loaded from: classes2.dex */
public final class c implements TypeEvaluator {
    public static final c b = new c();
    public final f a = new f();

    @Override // android.animation.TypeEvaluator
    public final Object evaluate(float f, Object obj, Object obj2) {
        f fVar = (f) obj;
        f fVar2 = (f) obj2;
        float f2 = fVar.a;
        float f3 = 1.0f - f;
        float f4 = (fVar2.a * f) + (f2 * f3);
        float f5 = fVar.b;
        float f6 = (fVar2.b * f) + (f5 * f3);
        float f7 = fVar.c;
        float f8 = (f * fVar2.c) + (f3 * f7);
        f fVar3 = this.a;
        fVar3.a = f4;
        fVar3.b = f6;
        fVar3.c = f8;
        return fVar3;
    }
}
