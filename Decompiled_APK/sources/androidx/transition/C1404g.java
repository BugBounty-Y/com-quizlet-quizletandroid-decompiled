package androidx.transition;

import android.animation.ObjectAnimator;
import android.view.View;
import android.view.ViewGroup;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.transition.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1404g extends W {
    public C1404g(int i) {
        this.F = i;
    }

    public static float W(I i, float f) {
        Float f2;
        return (i == null || (f2 = (Float) i.a.get("android:fade:transitionAlpha")) == null) ? f : f2.floatValue();
    }

    @Override // androidx.transition.W
    public final ObjectAnimator T(ViewGroup viewGroup, View view, I i, I i2) {
        L.a.getClass();
        return V(view, W(i, DefinitionKt.NO_Float_VALUE), 1.0f);
    }

    @Override // androidx.transition.W
    public final ObjectAnimator U(ViewGroup viewGroup, View view, I i, I i2) {
        Q q = L.a;
        q.getClass();
        ObjectAnimator objectAnimatorV = V(view, W(i, 1.0f), DefinitionKt.NO_Float_VALUE);
        if (objectAnimatorV == null) {
            q.c(view, W(i2, 1.0f));
        }
        return objectAnimatorV;
    }

    public final ObjectAnimator V(View view, float f, float f2) {
        if (f == f2) {
            return null;
        }
        L.a.c(view, f);
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(view, L.b, f2);
        C1403f c1403f = new C1403f(view);
        objectAnimatorOfFloat.addListener(c1403f);
        q().b(c1403f);
        return objectAnimatorOfFloat;
    }

    @Override // androidx.transition.y
    public final void h(I i) {
        W.R(i);
        View view = i.b;
        Float fValueOf = (Float) view.getTag(R.id.transition_pause_alpha);
        if (fValueOf == null) {
            fValueOf = view.getVisibility() == 0 ? Float.valueOf(L.a.a(view)) : Float.valueOf(DefinitionKt.NO_Float_VALUE);
        }
        i.a.put("android:fade:transitionAlpha", fValueOf);
    }

    @Override // androidx.transition.y
    public final boolean v() {
        return true;
    }
}
