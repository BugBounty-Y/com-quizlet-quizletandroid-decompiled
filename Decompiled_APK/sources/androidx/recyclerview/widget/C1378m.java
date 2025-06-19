package androidx.recyclerview.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import android.view.ViewPropertyAnimator;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.recyclerview.widget.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1378m extends AnimatorListenerAdapter {
    public final /* synthetic */ F0 a;
    public final /* synthetic */ int b;
    public final /* synthetic */ View c;
    public final /* synthetic */ int d;
    public final /* synthetic */ ViewPropertyAnimator e;
    public final /* synthetic */ C1386q f;

    public C1378m(C1386q c1386q, F0 f0, int i, View view, int i2, ViewPropertyAnimator viewPropertyAnimator) {
        this.f = c1386q;
        this.a = f0;
        this.b = i;
        this.c = view;
        this.d = i2;
        this.e = viewPropertyAnimator;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
        int i = this.b;
        View view = this.c;
        if (i != 0) {
            view.setTranslationX(DefinitionKt.NO_Float_VALUE);
        }
        if (this.d != 0) {
            view.setTranslationY(DefinitionKt.NO_Float_VALUE);
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        this.e.setListener(null);
        C1386q c1386q = this.f;
        F0 f0 = this.a;
        c1386q.c(f0);
        c1386q.p.remove(f0);
        c1386q.i();
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        this.f.getClass();
    }
}
