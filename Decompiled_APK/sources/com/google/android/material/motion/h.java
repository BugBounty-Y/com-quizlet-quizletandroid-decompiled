package com.google.android.material.motion;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class h extends AnimatorListenerAdapter {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ int b;
    public final /* synthetic */ i c;

    public h(i iVar, boolean z, int i) {
        this.c = iVar;
        this.a = z;
        this.b = i;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        i iVar = this.c;
        iVar.b.setTranslationX(DefinitionKt.NO_Float_VALUE);
        iVar.b(DefinitionKt.NO_Float_VALUE, this.a, this.b);
    }
}
