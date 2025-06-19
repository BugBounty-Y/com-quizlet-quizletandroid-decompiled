package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import androidx.appcompat.widget.k1;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class e extends a {
    public boolean g;
    public final /* synthetic */ ExtendedFloatingActionButton h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(ExtendedFloatingActionButton extendedFloatingActionButton, com.airbnb.lottie.network.d dVar) {
        super(extendedFloatingActionButton, dVar);
        this.h = extendedFloatingActionButton;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final int c() {
        return R.animator.mtrl_extended_fab_hide_motion_spec;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void d() {
        super.d();
        this.g = true;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void e() {
        this.d.b = null;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.h;
        extendedFloatingActionButton.t = 0;
        if (this.g) {
            return;
        }
        extendedFloatingActionButton.setVisibility(8);
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void f(Animator animator) {
        com.airbnb.lottie.network.d dVar = this.d;
        Animator animator2 = (Animator) dVar.b;
        if (animator2 != null) {
            animator2.cancel();
        }
        dVar.b = animator;
        this.g = false;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.h;
        extendedFloatingActionButton.setVisibility(0);
        extendedFloatingActionButton.t = 1;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void g() {
        this.h.setVisibility(8);
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final boolean h() {
        k1 k1Var = ExtendedFloatingActionButton.I;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.h;
        if (extendedFloatingActionButton.getVisibility() == 0) {
            if (extendedFloatingActionButton.t != 1) {
                return false;
            }
        } else if (extendedFloatingActionButton.t == 2) {
            return false;
        }
        return true;
    }
}
