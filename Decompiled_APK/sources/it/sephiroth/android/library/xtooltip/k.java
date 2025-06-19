package it.sephiroth.android.library.xtooltip;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public boolean b;
    public final /* synthetic */ l c;

    public /* synthetic */ k(l lVar, int i) {
        this.a = i;
        this.c = lVar;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animation) {
        switch (this.a) {
            case 0:
                Intrinsics.f(animation, "animation");
                super.onAnimationCancel(animation);
                this.b = true;
                break;
            default:
                Intrinsics.f(animation, "animation");
                super.onAnimationCancel(animation);
                this.b = true;
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        switch (this.a) {
            case 0:
                Intrinsics.f(animation, "animation");
                if (!this.b) {
                    l lVar = this.c;
                    if (lVar.isVisible()) {
                        int i = lVar.h + 1;
                        lVar.h = i;
                        if (i < lVar.j) {
                            lVar.d.start();
                            break;
                        }
                    }
                }
                break;
            default:
                Intrinsics.f(animation, "animation");
                if (!this.b) {
                    l lVar2 = this.c;
                    if (lVar2.isVisible() && lVar2.h < lVar2.j) {
                        AnimatorSet animatorSet = lVar2.e;
                        animatorSet.setStartDelay(0L);
                        animatorSet.start();
                        break;
                    }
                }
                break;
        }
    }
}
