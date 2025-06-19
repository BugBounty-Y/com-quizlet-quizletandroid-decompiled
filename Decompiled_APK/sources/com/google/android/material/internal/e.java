package com.google.android.material.internal;

import android.animation.ValueAnimator;
import android.view.View;
import androidx.appcompat.widget.ActionMenuView;

/* loaded from: classes2.dex */
public final class e implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final View b;
    public final View c;
    public final Object d;

    public e(ActionMenuView actionMenuView, ActionMenuView actionMenuView2) {
        this.a = 0;
        this.b = actionMenuView;
        this.c = actionMenuView2;
        this.d = new float[2];
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        switch (this.a) {
            case 0:
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                float[] fArr = (float[]) this.d;
                p.a(fFloatValue, fArr);
                ActionMenuView actionMenuView = (ActionMenuView) this.b;
                if (actionMenuView != null) {
                    actionMenuView.setAlpha(fArr[0]);
                }
                ActionMenuView actionMenuView2 = (ActionMenuView) this.c;
                if (actionMenuView2 != null) {
                    actionMenuView2.setAlpha(fArr[1]);
                    break;
                }
                break;
            default:
                ((com.google.android.material.tabs.f) this.d).c(this.b, this.c, valueAnimator.getAnimatedFraction());
                break;
        }
    }

    public e(com.google.android.material.tabs.f fVar, View view, View view2) {
        this.a = 1;
        this.d = fVar;
        this.b = view;
        this.c = view2;
    }
}
