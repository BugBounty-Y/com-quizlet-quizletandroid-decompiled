package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.transition.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1403f extends AnimatorListenerAdapter implements InterfaceC1419w {
    public final View a;
    public boolean b = false;

    public C1403f(View view) {
        this.a = view;
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void a() {
        View view = this.a;
        view.setTag(R.id.transition_pause_alpha, Float.valueOf(view.getVisibility() == 0 ? L.a.a(view) : DefinitionKt.NO_Float_VALUE));
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void b(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void c(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void f(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void g() {
        this.a.setTag(R.id.transition_pause_alpha, null);
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
        L.a.c(this.a, 1.0f);
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        onAnimationEnd(animator, false);
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        View view = this.a;
        if (view.hasOverlappingRendering() && view.getLayerType() == 0) {
            this.b = true;
            view.setLayerType(2, null);
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator, boolean z) {
        boolean z2 = this.b;
        View view = this.a;
        if (z2) {
            view.setLayerType(0, null);
        }
        if (z) {
            return;
        }
        Q q = L.a;
        q.c(view, 1.0f);
        q.getClass();
    }
}
