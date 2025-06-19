package com.google.android.material.floatingactionbutton;

import android.animation.ValueAnimator;
import android.graphics.Matrix;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class l implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ float a;
    public final /* synthetic */ float b;
    public final /* synthetic */ float c;
    public final /* synthetic */ float d;
    public final /* synthetic */ float e;
    public final /* synthetic */ float f;
    public final /* synthetic */ float g;
    public final /* synthetic */ Matrix h;
    public final /* synthetic */ q i;

    public l(q qVar, float f, float f2, float f3, float f4, float f5, float f6, float f7, Matrix matrix) {
        this.i = qVar;
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        this.e = f5;
        this.f = f6;
        this.g = f7;
        this.h = matrix;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
        q qVar = this.i;
        qVar.v.setAlpha(com.google.android.material.animation.a.b(this.a, this.b, DefinitionKt.NO_Float_VALUE, 0.2f, fFloatValue));
        FloatingActionButton floatingActionButton = qVar.v;
        float f = this.c;
        float f2 = this.d;
        floatingActionButton.setScaleX(com.google.android.material.animation.a.a(f, f2, fFloatValue));
        qVar.v.setScaleY(com.google.android.material.animation.a.a(this.e, f2, fFloatValue));
        float f3 = this.f;
        float f4 = this.g;
        qVar.p = com.google.android.material.animation.a.a(f3, f4, fFloatValue);
        float fA = com.google.android.material.animation.a.a(f3, f4, fFloatValue);
        Matrix matrix = this.h;
        qVar.a(fA, matrix);
        qVar.v.setImageMatrix(matrix);
    }
}
