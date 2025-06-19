package com.google.android.material.behavior;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewPropertyAnimator;
import androidx.appcompat.widget.C0076c;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.b;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.LinkedHashSet;

/* loaded from: classes2.dex */
public class HideBottomViewOnScrollBehavior<V extends View> extends b {
    public int b;
    public int c;
    public TimeInterpolator d;
    public TimeInterpolator e;
    public ViewPropertyAnimator i;
    public final LinkedHashSet a = new LinkedHashSet();
    public int f = 0;
    public int g = 2;
    public int h = 0;

    public HideBottomViewOnScrollBehavior() {
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
        this.f = view.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) view.getLayoutParams()).bottomMargin;
        this.b = AbstractC3430b4.d(view.getContext(), R.attr.motionDurationLong2, 225);
        this.c = AbstractC3430b4.d(view.getContext(), R.attr.motionDurationMedium4, 175);
        this.d = AbstractC3430b4.e(view.getContext(), R.attr.motionEasingEmphasizedInterpolator, com.google.android.material.animation.a.d);
        this.e = AbstractC3430b4.e(view.getContext(), R.attr.motionEasingEmphasizedInterpolator, com.google.android.material.animation.a.c);
        return false;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void p(CoordinatorLayout coordinatorLayout, View view, int i, int i2, int i3, int[] iArr) {
        LinkedHashSet linkedHashSet = this.a;
        if (i > 0) {
            if (this.g == 1) {
                return;
            }
            ViewPropertyAnimator viewPropertyAnimator = this.i;
            if (viewPropertyAnimator != null) {
                viewPropertyAnimator.cancel();
                view.clearAnimation();
            }
            this.g = 1;
            Iterator it2 = linkedHashSet.iterator();
            if (it2.hasNext()) {
                throw android.support.v4.media.session.a.d(it2);
            }
            this.i = view.animate().translationY(this.f + this.h).setInterpolator(this.e).setDuration(this.c).setListener(new C0076c(this, 4));
            return;
        }
        if (i >= 0 || this.g == 2) {
            return;
        }
        ViewPropertyAnimator viewPropertyAnimator2 = this.i;
        if (viewPropertyAnimator2 != null) {
            viewPropertyAnimator2.cancel();
            view.clearAnimation();
        }
        this.g = 2;
        Iterator it3 = linkedHashSet.iterator();
        if (it3.hasNext()) {
            throw android.support.v4.media.session.a.d(it3);
        }
        this.i = view.animate().translationY(0).setInterpolator(this.d).setDuration(this.b).setListener(new C0076c(this, 4));
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean t(CoordinatorLayout coordinatorLayout, View view, View view2, View view3, int i, int i2) {
        return i == 2;
    }

    public HideBottomViewOnScrollBehavior(Context context, AttributeSet attributeSet) {
    }
}
