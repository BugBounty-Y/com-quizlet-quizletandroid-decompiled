package com.quizlet.features.setpage;

import android.animation.Animator;
import android.os.Handler;
import android.view.View;
import android.view.ViewGroup;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements Animator.AnimatorListener {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ r b;
    public final /* synthetic */ int c;

    public q(boolean z, r rVar, int i) {
        this.a = z;
        this.b = rVar;
        this.c = i;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        if (this.a) {
            return;
        }
        r rVar = this.b;
        Object value = rVar.p.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((View) value).setVisibility(8);
        rVar.T().setVisibility(8);
        ViewGroup viewGroupO = rVar.O();
        ViewGroup.LayoutParams layoutParams = viewGroupO.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        }
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        marginLayoutParams.bottomMargin = rVar.X;
        viewGroupO.setLayoutParams(marginLayoutParams);
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        if (this.a) {
            r rVar = this.b;
            new Handler(rVar.getMainLooper()).postDelayed(new androidx.core.provider.a(rVar, this.c, 10), 1L);
        }
    }
}
