package com.google.android.material.snackbar;

import android.animation.ValueAnimator;

/* loaded from: classes2.dex */
public final class b implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ b(g gVar, int i, byte b) {
        this.a = i;
        this.b = gVar;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        g gVar = this.b;
        switch (this.a) {
            case 0:
                gVar.i.setAlpha(((Float) valueAnimator.getAnimatedValue()).floatValue());
                break;
            case 1:
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                gVar.i.setScaleX(fFloatValue);
                gVar.i.setScaleY(fFloatValue);
                break;
            case 2:
                int iIntValue = ((Integer) valueAnimator.getAnimatedValue()).intValue();
                androidx.interpolator.view.animation.a aVar = g.v;
                gVar.i.setTranslationY(iIntValue);
                break;
            default:
                int iIntValue2 = ((Integer) valueAnimator.getAnimatedValue()).intValue();
                androidx.interpolator.view.animation.a aVar2 = g.v;
                gVar.i.setTranslationY(iIntValue2);
                break;
        }
    }

    public b(g gVar, int i) {
        this.a = 2;
        this.b = gVar;
    }
}
