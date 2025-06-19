package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import androidx.appcompat.widget.k1;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class f extends a {
    public final /* synthetic */ ExtendedFloatingActionButton g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(ExtendedFloatingActionButton extendedFloatingActionButton, com.airbnb.lottie.network.d dVar) {
        super(extendedFloatingActionButton, dVar);
        this.g = extendedFloatingActionButton;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final int c() {
        return R.animator.mtrl_extended_fab_show_motion_spec;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void e() {
        this.d.b = null;
        this.g.t = 0;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void f(Animator animator) {
        com.airbnb.lottie.network.d dVar = this.d;
        Animator animator2 = (Animator) dVar.b;
        if (animator2 != null) {
            animator2.cancel();
        }
        dVar.b = animator;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.g;
        extendedFloatingActionButton.setVisibility(0);
        extendedFloatingActionButton.t = 2;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void g() {
        ExtendedFloatingActionButton extendedFloatingActionButton = this.g;
        extendedFloatingActionButton.setVisibility(0);
        extendedFloatingActionButton.setAlpha(1.0f);
        extendedFloatingActionButton.setScaleY(1.0f);
        extendedFloatingActionButton.setScaleX(1.0f);
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final boolean h() {
        k1 k1Var = ExtendedFloatingActionButton.I;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.g;
        if (extendedFloatingActionButton.getVisibility() != 0) {
            if (extendedFloatingActionButton.t != 2) {
                return false;
            }
        } else if (extendedFloatingActionButton.t == 1) {
            return false;
        }
        return true;
    }
}
