package androidx.appcompat.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class S0 extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public boolean b;
    public final /* synthetic */ Object c;

    public /* synthetic */ S0(Object obj, int i) {
        this.a = i;
        this.c = obj;
        this.b = false;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationCancel(Animator animator) {
        switch (this.a) {
            case 0:
                this.b = true;
                break;
            case 1:
                this.b = true;
                break;
            default:
                super.onAnimationCancel(animator);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                if (!this.b) {
                    ((T0) this.c).setVisibility(0);
                    break;
                }
                break;
            case 1:
                if (!this.b) {
                    androidx.recyclerview.widget.B b = (androidx.recyclerview.widget.B) this.c;
                    if (((Float) b.z.getAnimatedValue()).floatValue() != DefinitionKt.NO_Float_VALUE) {
                        b.A = 2;
                        b.s.invalidate();
                        break;
                    } else {
                        b.A = 0;
                        b.i(0);
                        break;
                    }
                } else {
                    this.b = false;
                    break;
                }
            case 2:
                float f = this.b ? 1.0f : 0.0f;
                Yh yh = (Yh) this.c;
                Yh.a(yh, f);
                ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) yh.d;
                clippableRoundedCornerLayout.a = null;
                clippableRoundedCornerLayout.b = DefinitionKt.NO_Float_VALUE;
                clippableRoundedCornerLayout.invalidate();
                break;
            default:
                if (!this.b) {
                    ((View) this.c).setVisibility(4);
                    break;
                }
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                ((T0) this.c).setVisibility(0);
                this.b = false;
                break;
            case 1:
            default:
                super.onAnimationStart(animator);
                break;
            case 2:
                Yh.a((Yh) this.c, this.b ? DefinitionKt.NO_Float_VALUE : 1.0f);
                break;
            case 3:
                if (this.b) {
                    ((View) this.c).setVisibility(0);
                    break;
                }
                break;
        }
    }

    public S0(View view, boolean z) {
        this.a = 3;
        this.b = z;
        this.c = view;
    }

    public S0(Yh yh, boolean z) {
        this.a = 2;
        this.c = yh;
        this.b = z;
    }
}
