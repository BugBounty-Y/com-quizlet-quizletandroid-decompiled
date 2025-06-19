package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.animation.Animator;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/* loaded from: classes3.dex */
public final class d implements Animator.AnimatorListener {
    public final /* synthetic */ FloatingActionButton a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ CardVisibilityFABBehavior c;

    public d(CardVisibilityFABBehavior cardVisibilityFABBehavior, FloatingActionButton floatingActionButton, boolean z) {
        this.c = cardVisibilityFABBehavior;
        this.a = floatingActionButton;
        this.b = z;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
        this.c.a = null;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        this.c.a = null;
        FloatingActionButton floatingActionButton = this.a;
        if (this.b) {
            floatingActionButton.setVisibility(0);
        } else {
            floatingActionButton.setVisibility(8);
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animator) {
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        this.a.setVisibility(0);
    }
}
