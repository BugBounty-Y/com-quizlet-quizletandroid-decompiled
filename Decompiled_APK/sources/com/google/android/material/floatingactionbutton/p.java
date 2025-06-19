package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public abstract class p extends AnimatorListenerAdapter implements ValueAnimator.AnimatorUpdateListener {
    public boolean a;
    public float b;
    public float c;
    public final /* synthetic */ s d;

    public p(s sVar) {
        this.d = sVar;
    }

    public abstract float a();

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        float f = (int) this.c;
        com.google.android.material.shape.g gVar = this.d.b;
        if (gVar != null) {
            gVar.l(f);
        }
        this.a = false;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        boolean z = this.a;
        s sVar = this.d;
        if (!z) {
            com.google.android.material.shape.g gVar = sVar.b;
            this.b = gVar == null ? DefinitionKt.NO_Float_VALUE : gVar.a.m;
            this.c = a();
            this.a = true;
        }
        float f = this.b;
        float animatedFraction = (int) ((valueAnimator.getAnimatedFraction() * (this.c - f)) + f);
        com.google.android.material.shape.g gVar2 = sVar.b;
        if (gVar2 != null) {
            gVar2.l(animatedFraction);
        }
    }
}
