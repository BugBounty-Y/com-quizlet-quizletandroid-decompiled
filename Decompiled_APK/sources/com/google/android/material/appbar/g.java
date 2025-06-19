package com.google.android.material.appbar;

import android.animation.ValueAnimator;
import android.view.View;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.textfield.TextInputLayout;

/* loaded from: classes2.dex */
public final class g implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ g(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        switch (this.a) {
            case 0:
                ((CollapsingToolbarLayout) this.b).setScrimAlpha(((Integer) valueAnimator.getAnimatedValue()).intValue());
                break;
            case 1:
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                com.google.android.material.shape.g gVar = ((BottomSheetBehavior) this.b).i;
                if (gVar != null) {
                    gVar.n(fFloatValue);
                    break;
                }
                break;
            case 2:
                ((com.google.android.material.tabs.l) this.b).scrollTo(((Integer) valueAnimator.getAnimatedValue()).intValue(), 0);
                break;
            case 3:
                ((TextInputLayout) this.b).F1.p(((Float) valueAnimator.getAnimatedValue()).floatValue());
                break;
            default:
                ((View) this.b).invalidate();
                break;
        }
    }
}
