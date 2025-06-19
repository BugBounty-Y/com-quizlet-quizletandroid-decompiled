package com.google.android.material.bottomappbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/* loaded from: classes2.dex */
public final class a extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ BottomAppBar b;

    public /* synthetic */ a(BottomAppBar bottomAppBar, int i) {
        this.a = i;
        this.b = bottomAppBar;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationEnd(Animator animator) {
        BottomAppBar bottomAppBar = this.b;
        switch (this.a) {
            case 1:
                int i = BottomAppBar.E1;
                bottomAppBar.j1 = null;
                break;
            case 2:
                int i2 = BottomAppBar.E1;
                bottomAppBar.getClass();
                bottomAppBar.w1 = false;
                bottomAppBar.k1 = null;
                break;
            default:
                super.onAnimationEnd(animator);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        BottomAppBar bottomAppBar = this.b;
        switch (this.a) {
            case 0:
                if (!bottomAppBar.w1) {
                    bottomAppBar.G(bottomAppBar.l1, bottomAppBar.x1);
                    break;
                }
                break;
            case 1:
                int i = BottomAppBar.E1;
                break;
            case 2:
                int i2 = BottomAppBar.E1;
                bottomAppBar.getClass();
                break;
            default:
                bottomAppBar.C1.onAnimationStart(animator);
                View viewC = bottomAppBar.C();
                FloatingActionButton floatingActionButton = viewC instanceof FloatingActionButton ? (FloatingActionButton) viewC : null;
                if (floatingActionButton != null) {
                    floatingActionButton.setTranslationX(bottomAppBar.getFabTranslationX());
                    break;
                }
                break;
        }
    }
}
