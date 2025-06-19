package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import android.view.ViewGroup;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class U extends AnimatorListenerAdapter implements InterfaceC1419w {
    public final ViewGroup a;
    public final View b;
    public final View c;
    public boolean d = true;
    public final /* synthetic */ W e;

    public U(W w, ViewGroup viewGroup, View view, View view2) {
        this.e = w;
        this.a = viewGroup;
        this.b = view;
        this.c = view2;
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void a() {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void b(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
        yVar.D(this);
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void f(y yVar) {
        if (this.d) {
            h();
        }
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void g() {
    }

    public final void h() {
        this.c.setTag(R.id.save_overlay_view, null);
        this.a.getOverlay().remove(this.b);
        this.d = false;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        h();
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
    public final void onAnimationPause(Animator animator) {
        this.a.getOverlay().remove(this.b);
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
    public final void onAnimationResume(Animator animator) {
        View view = this.b;
        if (view.getParent() == null) {
            this.a.getOverlay().add(view);
        } else {
            this.e.cancel();
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator, boolean z) {
        if (z) {
            View view = this.c;
            View view2 = this.b;
            view.setTag(R.id.save_overlay_view, view2);
            this.a.getOverlay().add(view2);
            this.d = true;
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator, boolean z) {
        if (z) {
            return;
        }
        h();
    }
}
