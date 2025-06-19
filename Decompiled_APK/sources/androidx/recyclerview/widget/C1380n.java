package androidx.recyclerview.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import android.view.ViewPropertyAnimator;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.recyclerview.widget.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1380n extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1382o b;
    public final /* synthetic */ ViewPropertyAnimator c;
    public final /* synthetic */ View d;
    public final /* synthetic */ C1386q e;

    public /* synthetic */ C1380n(C1386q c1386q, C1382o c1382o, ViewPropertyAnimator viewPropertyAnimator, View view, int i) {
        this.a = i;
        this.e = c1386q;
        this.b = c1382o;
        this.c = viewPropertyAnimator;
        this.d = view;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                this.c.setListener(null);
                View view = this.d;
                view.setAlpha(1.0f);
                view.setTranslationX(DefinitionKt.NO_Float_VALUE);
                view.setTranslationY(DefinitionKt.NO_Float_VALUE);
                C1382o c1382o = this.b;
                F0 f0 = c1382o.a;
                C1386q c1386q = this.e;
                c1386q.c(f0);
                c1386q.r.remove(c1382o.a);
                c1386q.i();
                break;
            default:
                this.c.setListener(null);
                View view2 = this.d;
                view2.setAlpha(1.0f);
                view2.setTranslationX(DefinitionKt.NO_Float_VALUE);
                view2.setTranslationY(DefinitionKt.NO_Float_VALUE);
                C1382o c1382o2 = this.b;
                F0 f02 = c1382o2.b;
                C1386q c1386q2 = this.e;
                c1386q2.c(f02);
                c1386q2.r.remove(c1382o2.b);
                c1386q2.i();
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                F0 f0 = this.b.a;
                this.e.getClass();
                break;
            default:
                F0 f02 = this.b.b;
                this.e.getClass();
                break;
        }
    }
}
