package androidx.swiperefreshlayout.widget;

import android.animation.Animator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class c implements Animator.AnimatorListener {
    public final /* synthetic */ d a;
    public final /* synthetic */ e b;

    public c(e eVar, d dVar) {
        this.b = eVar;
        this.a = dVar;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animator) {
        e eVar = this.b;
        d dVar = this.a;
        eVar.a(1.0f, dVar, true);
        dVar.k = dVar.e;
        dVar.l = dVar.f;
        dVar.m = dVar.g;
        dVar.a((dVar.j + 1) % dVar.i.length);
        if (!eVar.f) {
            eVar.e += 1.0f;
            return;
        }
        eVar.f = false;
        animator.cancel();
        animator.setDuration(1332L);
        animator.start();
        if (dVar.n) {
            dVar.n = false;
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        this.b.e = DefinitionKt.NO_Float_VALUE;
    }
}
