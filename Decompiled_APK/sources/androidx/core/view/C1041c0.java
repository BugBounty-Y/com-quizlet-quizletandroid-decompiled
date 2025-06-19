package androidx.core.view;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.collection.C0208f;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.core.view.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1041c0 extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1041c0(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationCancel(Animator animation) {
        switch (this.a) {
            case 0:
                ((InterfaceC1045e0) this.c).a();
                break;
            case 4:
                Intrinsics.checkNotNullParameter(animation, "animation");
                ((MatchCardView) this.c).setSelectedState(false);
                ((io.reactivex.rxjava3.subjects.f) this.b).onComplete();
                break;
            default:
                super.onAnimationCancel(animation);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        switch (this.a) {
            case 0:
                ((InterfaceC1045e0) this.c).c();
                break;
            case 1:
                m0 m0Var = (m0) this.c;
                m0Var.a.d(1.0f);
                i0.e((View) this.b, m0Var);
                break;
            case 2:
                ((C0208f) this.c).remove(animation);
                ((androidx.transition.y) this.b).n.remove(animation);
                break;
            case 3:
                ((com.google.android.material.circularreveal.g) this.c).setCircularRevealOverlayDrawable(null);
                break;
            default:
                Intrinsics.checkNotNullParameter(animation, "animation");
                ((MatchCardView) this.c).setSelectedState(false);
                ((io.reactivex.rxjava3.subjects.f) this.b).onComplete();
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                ((InterfaceC1045e0) this.c).b();
                break;
            case 1:
            default:
                super.onAnimationStart(animator);
                break;
            case 2:
                ((androidx.transition.y) this.b).n.add(animator);
                break;
            case 3:
                ((com.google.android.material.circularreveal.g) this.c).setCircularRevealOverlayDrawable((Drawable) this.b);
                break;
        }
    }

    public C1041c0(androidx.transition.y yVar, C0208f c0208f) {
        this.a = 2;
        this.b = yVar;
        this.c = c0208f;
    }
}
