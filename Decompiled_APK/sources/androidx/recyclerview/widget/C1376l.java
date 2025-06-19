package androidx.recyclerview.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import android.view.ViewPropertyAnimator;

/* renamed from: androidx.recyclerview.widget.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1376l extends AnimatorListenerAdapter {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ F0 b;
    public final /* synthetic */ View c;
    public final /* synthetic */ ViewPropertyAnimator d;
    public final /* synthetic */ C1386q e;

    public C1376l(C1386q c1386q, F0 f0, ViewPropertyAnimator viewPropertyAnimator, View view) {
        this.e = c1386q;
        this.b = f0;
        this.d = viewPropertyAnimator;
        this.c = view;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationCancel(Animator animator) {
        switch (this.a) {
            case 1:
                this.c.setAlpha(1.0f);
                break;
            default:
                super.onAnimationCancel(animator);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                this.d.setListener(null);
                this.c.setAlpha(1.0f);
                C1386q c1386q = this.e;
                F0 f0 = this.b;
                c1386q.c(f0);
                c1386q.q.remove(f0);
                c1386q.i();
                break;
            default:
                this.d.setListener(null);
                C1386q c1386q2 = this.e;
                F0 f02 = this.b;
                c1386q2.c(f02);
                c1386q2.o.remove(f02);
                c1386q2.i();
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                this.e.getClass();
                break;
            default:
                this.e.getClass();
                break;
        }
    }

    public C1376l(C1386q c1386q, F0 f0, View view, ViewPropertyAnimator viewPropertyAnimator) {
        this.e = c1386q;
        this.b = f0;
        this.c = view;
        this.d = viewPropertyAnimator;
    }
}
