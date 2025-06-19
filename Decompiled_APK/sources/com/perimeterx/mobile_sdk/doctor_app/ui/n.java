package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.animation.Animator;
import java.io.UnsupportedEncodingException;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n implements Animator.AnimatorListener {
    public final /* synthetic */ int a = 1;
    public InterfaceC4938g b;

    public /* synthetic */ n() {
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animation) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(animation, "animation");
                break;
            default:
                Intrinsics.f(animation, "animation");
                break;
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(animation, "animation");
                ((Function0) this.b).invoke();
                break;
            default:
                Intrinsics.f(animation, "animation");
                androidx.compose.ui.viewinterop.b bVar = (androidx.compose.ui.viewinterop.b) this.b;
                if (bVar != null) {
                    bVar.invoke(animation);
                    break;
                }
                break;
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animation) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(animation, "animation");
                break;
            default:
                Intrinsics.f(animation, "animation");
                break;
        }
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(animation, "animation");
                break;
            default:
                Intrinsics.f(animation, "animation");
                break;
        }
    }

    public n(Function0 function0) {
        this.b = function0;
    }
}
