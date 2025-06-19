package androidx.recyclerview.widget;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class G implements Animator.AnimatorListener {
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final F0 e;
    public final int f;
    public final ValueAnimator g;
    public boolean h;
    public float i;
    public float j;
    public boolean k = false;
    public boolean l = false;
    public float m;
    public final /* synthetic */ int n;
    public final /* synthetic */ F0 o;
    public final /* synthetic */ L p;

    public G(L l, F0 f0, int i, float f, float f2, float f3, float f4, int i2, F0 f02) {
        this.p = l;
        this.n = i2;
        this.o = f02;
        this.f = i;
        this.e = f0;
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        this.g = valueAnimatorOfFloat;
        valueAnimatorOfFloat.addUpdateListener(new A(this, 1));
        valueAnimatorOfFloat.setTarget(f0.itemView);
        valueAnimatorOfFloat.addListener(this);
        this.m = DefinitionKt.NO_Float_VALUE;
    }

    public final void a(Animator animator) {
        if (!this.l) {
            this.e.setIsRecyclable(true);
        }
        this.l = true;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
        this.m = 1.0f;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        a(animator);
        if (this.k) {
            return;
        }
        int i = this.n;
        F0 f0 = this.o;
        L l = this.p;
        if (i <= 0) {
            l.m.clearView(l.r, f0);
        } else {
            l.a.add(f0.itemView);
            this.h = true;
            if (i > 0) {
                l.r.post(new androidx.appcompat.widget.V(l, this, i, 3, false));
            }
        }
        View view = l.w;
        View view2 = f0.itemView;
        if (view == view2) {
            l.o(view2);
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animator) {
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
    }
}
