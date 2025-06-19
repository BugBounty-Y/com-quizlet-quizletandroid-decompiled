package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.animation.Animator;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements Animator.AnimatorListener {
    public final /* synthetic */ F a;
    public final /* synthetic */ com.braze.triggers.managers.h b;

    public b(F f, com.braze.triggers.managers.h hVar) {
        this.a = f;
        this.b = hVar;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation, boolean z) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        F f = this.a;
        if (f.a) {
            return;
        }
        f.a = true;
        com.braze.triggers.managers.h hVar = this.b;
        if (hVar != null) {
            hVar.invoke();
        }
        com.braze.triggers.managers.h hVar2 = PXDoctorActivity.i;
        if (hVar2 != null) {
            hVar2.invoke();
        }
        PXDoctorActivity.i = null;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation, boolean z) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }
}
