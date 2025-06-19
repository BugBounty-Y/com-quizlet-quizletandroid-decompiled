package com.airbnb.lottie;

import android.animation.ValueAnimator;
import android.view.ViewGroup;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class s implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ s(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        switch (this.a) {
            case 0:
                u uVar = (u) this.b;
                EnumC1461a enumC1461a = uVar.L;
                if (enumC1461a == null) {
                    enumC1461a = EnumC1461a.a;
                }
                if (enumC1461a != EnumC1461a.b) {
                    com.airbnb.lottie.model.layer.c cVar = uVar.o;
                    if (cVar != null) {
                        cVar.r(uVar.b.b());
                        break;
                    }
                } else {
                    uVar.invalidateSelf();
                    break;
                }
                break;
            case 1:
                com.google.android.material.card.d dVar = (com.google.android.material.card.d) this.b;
                dVar.getClass();
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                dVar.j.setAlpha((int) (255.0f * fFloatValue));
                dVar.x = fFloatValue;
                break;
            case 2:
                float fFloatValue2 = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                ((ClippableRoundedCornerLayout) this.b).a(r0.getLeft(), r0.getTop(), r0.getRight(), r0.getBottom(), fFloatValue2);
                break;
            case 3:
                float fFloatValue3 = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                androidx.appcompat.graphics.drawable.a aVar = (androidx.appcompat.graphics.drawable.a) this.b;
                if (aVar.i != fFloatValue3) {
                    aVar.i = fFloatValue3;
                    aVar.invalidateSelf();
                    break;
                }
                break;
            case 4:
                ((com.google.android.material.internal.d) this.b).a(((Float) valueAnimator.getAnimatedValue()).floatValue());
                break;
            case 5:
                com.google.android.material.textfield.i iVar = (com.google.android.material.textfield.i) this.b;
                iVar.getClass();
                iVar.d.setAlpha(((Float) valueAnimator.getAnimatedValue()).floatValue());
                break;
            default:
                Intrinsics.checkNotNullParameter(valueAnimator, "valueAnimator");
                com.quizlet.features.setpage.r rVar = (com.quizlet.features.setpage.r) this.b;
                ViewGroup.LayoutParams layoutParams = rVar.T().getLayoutParams();
                Intrinsics.e(layoutParams, "null cannot be cast to non-null type androidx.constraintlayout.widget.ConstraintLayout.LayoutParams");
                Object animatedValue = valueAnimator.getAnimatedValue();
                Intrinsics.e(animatedValue, "null cannot be cast to non-null type kotlin.Int");
                ((ViewGroup.MarginLayoutParams) ((androidx.constraintlayout.widget.e) layoutParams)).height = ((Integer) animatedValue).intValue();
                rVar.T().requestLayout();
                break;
        }
    }
}
