package com.google.android.material.snackbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.TimeInterpolator;
import android.view.ViewPropertyAnimator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class a extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ g c;

    public /* synthetic */ a(g gVar, int i, int i2) {
        this.a = i2;
        this.c = gVar;
        this.b = i;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                this.c.c(this.b);
                break;
            default:
                this.c.c(this.b);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 1:
                g gVar = this.c;
                SnackbarContentLayout snackbarContentLayout = gVar.j;
                snackbarContentLayout.a.setAlpha(1.0f);
                ViewPropertyAnimator viewPropertyAnimatorAlpha = snackbarContentLayout.a.animate().alpha(DefinitionKt.NO_Float_VALUE);
                long j = gVar.b;
                ViewPropertyAnimator duration = viewPropertyAnimatorAlpha.setDuration(j);
                TimeInterpolator timeInterpolator = snackbarContentLayout.c;
                long j2 = 0;
                duration.setInterpolator(timeInterpolator).setStartDelay(j2).start();
                if (snackbarContentLayout.b.getVisibility() == 0) {
                    snackbarContentLayout.b.setAlpha(1.0f);
                    snackbarContentLayout.b.animate().alpha(DefinitionKt.NO_Float_VALUE).setDuration(j).setInterpolator(timeInterpolator).setStartDelay(j2).start();
                    break;
                }
                break;
            default:
                super.onAnimationStart(animator);
                break;
        }
    }
}
