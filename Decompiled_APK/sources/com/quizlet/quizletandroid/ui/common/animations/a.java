package com.quizlet.quizletandroid.ui.common.animations;

import android.view.animation.Animation;
import android.view.animation.Transformation;
import android.widget.LinearLayout;

/* loaded from: classes3.dex */
public final class a extends Animation {
    public final LinearLayout a;
    public final float b;
    public final int c;

    public a(LinearLayout linearLayout, int i) {
        setDuration(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
        this.a = linearLayout;
        this.b = linearLayout.getLayoutParams().height;
        this.c = i;
        if (i == 2) {
            linearLayout.getLayoutParams().height = 0;
            linearLayout.setVisibility(0);
        }
    }

    @Override // android.view.animation.Animation
    public final void applyTransformation(float f, Transformation transformation) {
        super.applyTransformation(f, transformation);
        int i = this.c;
        float f2 = this.b;
        LinearLayout linearLayout = this.a;
        if (f < 1.0f) {
            if (i == 2) {
                linearLayout.getLayoutParams().height = (int) (f2 * f);
            } else {
                linearLayout.getLayoutParams().height = (int) (f2 - (f * f2));
            }
            linearLayout.requestLayout();
            return;
        }
        if (i == 2) {
            linearLayout.getLayoutParams().height = (int) f2;
            linearLayout.requestLayout();
        } else {
            linearLayout.getLayoutParams().height = 0;
            linearLayout.setVisibility(8);
            linearLayout.requestLayout();
            linearLayout.getLayoutParams().height = (int) f2;
        }
    }
}
