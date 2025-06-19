package androidx.transition;

import android.animation.ObjectAnimator;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2;

/* loaded from: classes.dex */
public final class r extends W {
    public static final DecelerateInterpolator I = new DecelerateInterpolator();
    public static final AccelerateInterpolator J = new AccelerateInterpolator();
    public static final C1413p K = new C1413p();
    public InterfaceC1414q H;

    @Override // androidx.transition.W
    public final ObjectAnimator T(ViewGroup viewGroup, View view, I i, I i2) {
        if (i2 == null) {
            return null;
        }
        int[] iArr = (int[]) i2.a.get("android:slide:screenPosition");
        float translationX = view.getTranslationX();
        float translationY = view.getTranslationY();
        return AbstractC3363l2.c(view, i2, iArr[0], iArr[1], this.H.a(view, viewGroup), this.H.b(view, viewGroup), translationX, translationY, I, this);
    }

    @Override // androidx.transition.W
    public final ObjectAnimator U(ViewGroup viewGroup, View view, I i, I i2) {
        if (i == null) {
            return null;
        }
        int[] iArr = (int[]) i.a.get("android:slide:screenPosition");
        return AbstractC3363l2.c(view, i, iArr[0], iArr[1], view.getTranslationX(), view.getTranslationY(), this.H.a(view, viewGroup), this.H.b(view, viewGroup), J, this);
    }

    @Override // androidx.transition.W, androidx.transition.y
    public final void e(I i) {
        W.R(i);
        int[] iArr = new int[2];
        i.b.getLocationOnScreen(iArr);
        i.a.put("android:slide:screenPosition", iArr);
    }

    @Override // androidx.transition.y
    public final void h(I i) {
        W.R(i);
        int[] iArr = new int[2];
        i.b.getLocationOnScreen(iArr);
        i.a.put("android:slide:screenPosition", iArr);
    }

    @Override // androidx.transition.y
    public final boolean v() {
        return true;
    }
}
